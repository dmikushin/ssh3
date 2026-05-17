package ssh3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/francoismichel/ssh3/util"
	"golang.org/x/exp/slices"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

const SSH_FRAME_TYPE = 0xaf3627e6

type ConversationID [32]byte

func (cid ConversationID) String() string {
	return base64.StdEncoding.EncodeToString(cid[:])
}

// controlStreamLike is the small subset of methods we use on the
// HTTP/3 control stream of a conversation. It is satisfied by both
// *http3.Stream (server side, where the stream is delivered to us by
// the HTTP/3 handler) and *http3.RequestStream (client side, where we
// open it ourselves via http3.ClientConn.OpenRequestStream because
// the v0.57.1 transport no longer exposes DontCloseRequestStream).
type controlStreamLike interface {
	StreamID() quic.StreamID
	Close() error
}

type Conversation struct {
	controlStream             controlStreamLike
	maxPacketSize             uint64
	defaultDatagramsQueueSize uint64
	streamCreator             *quic.Conn
	messageSender             util.DatagramSender
	channelsManager           *channelsManager
	context                   context.Context
	cancelContext             context.CancelCauseFunc
	conversationID            ConversationID // generated using TLS exporters
	peerVersion               Version

	channelsAcceptQueue *util.AcceptQueue[Channel]
}

func GenerateConversationID(tls *tls.ConnectionState) (convID ConversationID, err error) {
	ret, err := tls.ExportKeyingMaterial("EXPORTER-SSH3", nil, 32)
	if err != nil {
		return convID, err
	}
	if len(ret) != len(convID) {
		return convID, fmt.Errorf("TLS returned a tls-exporter with the wrong length (%d instead of %d)", len(ret), len(convID))
	}
	copy(convID[:], ret)
	return convID, err
}

func NewClientConversation(maxPacketsize uint64, defaultDatagramsQueueSize uint64, tls *tls.ConnectionState) (*Conversation, error) {
	convID, err := GenerateConversationID(tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID: %s", err)
		return nil, err
	}
	backgroundCtx, backgroundCancelCauseFunc := context.WithCancelCause(context.Background())
	conv := &Conversation{
		controlStream:             nil,
		channelsAcceptQueue:       util.NewAcceptQueue[Channel](),
		streamCreator:             nil,
		maxPacketSize:             maxPacketsize,
		defaultDatagramsQueueSize: defaultDatagramsQueueSize,
		channelsManager:           newChannelsManager(),
		context:                   backgroundCtx,
		cancelContext:             backgroundCancelCauseFunc,
		conversationID:            convID,

		// peerVersion set afterwards
	}
	return conv, nil
}

func (c *Conversation) EstablishClientConversation(req *http.Request, roundTripper *http3.Transport, qconn *quic.Conn, supportedVersions []Version) error {

	roundTripper.StreamHijacker = func(frameType http3.FrameType, _ quic.ConnectionTracingID, stream *quic.Stream, err error) (bool, error) {
		if err != nil {
			return false, err
		}
		if frameType != SSH_FRAME_TYPE {
			return false, nil
		}

		controlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
		if err != nil {
			return false, err
		}
		// todo: handle several conversations for the same client on the same connection ?
		// This can be done by defining the conversation ID as a combination between the control stream ID
		// and the tls exporter value, or computing the exporter value depending on the stream ID
		if controlStreamID != uint64(c.controlStream.StreamID()) {
			err := fmt.Errorf("wrong conversation control stream ID: %d instead of expected %d", controlStreamID, c.controlStream.StreamID())
			log.Error().Msgf("%s", err)
			return false, err
		}
		channelInfo := &ChannelInfo{
			ConversationID:       c.ConversationID(),
			ConversationStreamID: controlStreamID,
			ChannelID:            uint64(stream.StreamID()),
			ChannelType:          channelType,
			MaxPacketSize:        maxPacketSize,
		}

		newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, nil, c.channelsManager, false, false, true, c.defaultDatagramsQueueSize, nil)
		newChannel.setDatagramSender(c.getDatagramSenderForChannel(newChannel.ChannelID()))

		// Server-initiated reverse-forward data channels carry the
		// server-side bind address in their header additional bytes
		// (see Conversation.OpenTCPReverseForwardingChannel and the
		// UDP variant).  Decode it here so the central client-side
		// dispatcher can route the channel by bind address.  Any
		// parse error means the peer is sending us malformed reverse-
		// forward channels; surface it instead of silently demoting
		// the channel to a generic one.
		switch channelInfo.ChannelType {
		case "open-request-reverse-tcp":
			bind, err := parseTCPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
			if err != nil {
				log.Error().Msgf("parse open-request-reverse-tcp header: %s", err)
				return false, err
			}
			c.channelsAcceptQueue.Add(&TCPOpenReverseForwardingChannelImpl{Channel: newChannel, BindAddr: bind})
			return true, nil
		case "open-request-reverse-udp":
			bind, err := parseUDPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
			if err != nil {
				log.Error().Msgf("parse open-request-reverse-udp header: %s", err)
				return false, err
			}
			c.channelsAcceptQueue.Add(&UDPOpenReverseForwardingChannelImpl{Channel: newChannel, BindAddr: bind})
			return true, nil
		}

		c.channelsAcceptQueue.Add(newChannel)
		return true, nil
	}

	// Build a single *http3.ClientConn on top of our already-handshaken
	// QUIC connection. The old code relied on http3.Transport.RoundTripOpt
	// with DontCloseRequestStream so the underlying request stream stayed
	// open after ReadResponse, which is what ssh3 needs for its long-lived
	// CONNECT-style control stream. DontCloseRequestStream was removed in
	// quic-go v0.57.1; the supported replacement is to drive the request
	// manually through *http3.ClientConn.OpenRequestStream, which by
	// design does NOT close the stream when ReadResponse returns. That
	// restores the long-lived CONNECT semantics.
	//
	// roundTripper.StreamHijacker is set above; NewClientConn snapshots it,
	// so this call must come after the hijacker is installed. qconn is
	// already past HandshakeComplete by the time we get here (see
	// client/client.go just before NewClientConversation), so there is no
	// chicken-and-egg ordering problem with OpenRequestStream.
	clientConn := roundTripper.NewClientConn(qconn)

	// doReq keeps its (response, server-version, error) signature; the
	// underlying *http3.RequestStream that backs the long-lived control
	// stream is stashed via the closure into the returned response by
	// way of c.controlStream below — there is exactly one successful
	// doReq call per conversation (after at most one version-fallback
	// retry), so we don't need to thread the RequestStream through the
	// return values.
	var lastReqStream *http3.RequestStream
	doReq := func(version Version, req *http.Request) (*http.Response, Version, error) {
		req.Header.Set("User-Agent", version.GetVersionString())
		log.Debug().Msgf("send %s request on URL %s, User-Agent=\"%s\"", req.Method, req.URL, req.Header.Get("User-Agent"))
		str, err := clientConn.OpenRequestStream(req.Context())
		if err != nil {
			return nil, Version{}, err
		}
		if err := str.SendRequestHeader(req); err != nil {
			str.CancelRead(0)
			str.CancelWrite(0)
			return nil, Version{}, err
		}
		rsp, err := str.ReadResponse()
		if err != nil {
			return nil, Version{}, err
		}
		// Hold on to the stream so EstablishClientConversation can adopt
		// it as the control stream once it has decided this response is
		// the final one (i.e. not a version-negotiation 403).
		lastReqStream = str

		log.Debug().Msgf("got response with %s status code", rsp.Status)

		serverVersionStr := rsp.Header.Get("Server")
		serverVersion, err := ParseVersionString(serverVersionStr)
		if err != nil {
			log.Error().Msgf("Could not parse server version: \"%s\"", serverVersionStr)
			if rsp.StatusCode == 200 {
				return rsp, Version{}, InvalidSSHVersion{versionString: serverVersionStr}
			}
		} else {
			log.Debug().Msgf("server has valid version \"%s\" (protocol version = %s, software version = %s)",
				serverVersionStr, serverVersion.GetProtocolVersion(), serverVersion.GetSoftwareVersion())
		}
		return rsp, serverVersion, nil
	}

	rsp, serverVersion, err := doReq(ThisVersion(), req)
	if err != nil {
		return err
	}

	serverProtocolVersion := serverVersion.GetProtocolVersion()
	thisProtocolVersion := ThisVersion().GetProtocolVersion()
	if rsp.StatusCode == http.StatusForbidden && serverProtocolVersion != thisProtocolVersion {
		// This version negotiation code might feel a bit heavy but is only there for a smooth transition
		// between early versions and versions coming from an actual IETF specification that include
		// proper version negotiation. Older version of this implementation strictly check the exact protocol
		// version (i.e. must be 3.0) and then check the software version. In next iterations, everything will be
		// based on the protocol version for better interoperability.

		// see if there is an exact version match (including software version, which is useful
		// for old versions that do not support version negotiation based on the protocol version)
		matchingVersionIndex := slices.Index(supportedVersions, serverVersion)

		// there is no exact match, the implementation/software version might differ, but the
		// protocol version may still match
		if matchingVersionIndex == -1 {
			matchingVersionIndex = slices.IndexFunc(supportedVersions, func(supportedVersion Version) bool {
				return serverProtocolVersion == supportedVersion.GetProtocolVersion()
			})
		}
		if matchingVersionIndex != -1 {
			log.Warn().Msgf("The server runs an old version of the protocol (%s). This software is still experimental, "+
				"you may want to update the server version before support is removed. Also, note that connecting to old "+
				"servers may increase the connection establishment time.", serverVersion.GetVersionString())
			// now retry the request with the compatible version
			rsp, serverVersion, err = doReq(supportedVersions[matchingVersionIndex], req)
			if err != nil {
				return err
			}
		}
	}

	if rsp.StatusCode == 200 {
		if !IsVersionSupported(serverVersion) {
			log.Warn().Msgf("The server runs an unsupported SSH version (%s), you may want to consider to update the client (currently %s)",
				serverVersion.GetProtocolVersion(), ThisVersion().GetProtocolVersion())
		}
		c.controlStream = lastReqStream
		c.streamCreator = qconn
		c.messageSender = qconn
		c.context, c.cancelContext = context.WithCancelCause(qconn.Context())
		go func() {
			// TODO: this hijacks the datagrams for the whole quic connection, so the server
			//		 currently does not work for several conversations in the same QUIC connection

			for {
				dgram, err := qconn.ReceiveDatagram(c.Context())
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not receive message from conn: %s", err)
					}
					return
				}
				buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
				convID, err := util.ReadVarInt(buf)
				if err != nil {
					log.Error().Msgf("could not read conv id from datagram on conv %d: %s", c.controlStream.StreamID(), err)
					return
				}
				if convID == uint64(c.controlStream.StreamID()) {
					err = c.AddDatagram(c.Context(), dgram[buf.Size()-int64(buf.Len()):])
					if err != nil {
						log.Error().Msgf("could not add datagram to conv id %d: %s", c.controlStream.StreamID(), err)
						return
					}
				} else {
					log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
				}
			}
		}()
		c.peerVersion = serverVersion
		// Synchronisation: read the one-byte conversation-ready ack the
		// server writes on the CONNECT stream after addConversation.
		// In quic-go v0.57+ the http3 handler invocation is not
		// strictly ordered against the next stream the client opens,
		// so without this read the very first reverse-forward channel
		// can lose the race against addConversation and get rejected
		// with H3_FRAME_UNEXPECTED by the StreamHijacker.  The ack is
		// also a soft proof that the server actually accepted the
		// conversation (not just the CONNECT headers).
		var ack [1]byte
		if _, err := io.ReadFull(lastReqStream, ack[:]); err != nil {
			log.Warn().Msgf("could not read conversation-ready ack from server: %s (continuing anyway)", err)
		}
		return nil
	} else if rsp.StatusCode == http.StatusUnauthorized {
		return util.Unauthorized{}
	} else {
		bodyContent, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		if err != nil {
			log.Error().Msgf("could not read response body from server: %s", err)
		}

		return util.OtherHTTPError{
			HasBody:    rsp.ContentLength > 0,
			Body:       string(bodyContent),
			StatusCode: rsp.StatusCode,
		}
	}
}

func NewServerConversation(ctx context.Context, controlStream *http3.Stream, qconn *quic.Conn, messageSender util.DatagramSender, maxPacketsize uint64, peerVersion Version) (*Conversation, error) {
	backgroundContext, backgroundCancelFunc := context.WithCancelCause(ctx)

	tls := qconn.ConnectionState().TLS
	convID, err := GenerateConversationID(&tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID on server")
		return nil, err
	}

	conv := &Conversation{
		controlStream:       controlStream,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       qconn,
		maxPacketSize:       maxPacketsize,
		messageSender:       messageSender,
		channelsManager:     newChannelsManager(),
		context:             backgroundContext,
		cancelContext:       backgroundCancelFunc,
		conversationID:      convID,
		peerVersion:         peerVersion,
	}
	return conv, nil
}

// StreamByteReader wraps a *quic.Stream (or anything that implements
// the bidirectional-stream subset we need) so that it satisfies the
// channelReceiver interface and exposes ReadByte for parsers that use
// util.NewReader.
type StreamByteReader struct {
	stream streamLike
}

// streamLike is the read-side subset of *quic.Stream and *quic.ReceiveStream.
type streamLike interface {
	io.Reader
	CancelRead(quic.StreamErrorCode)
}

func (r *StreamByteReader) Read(p []byte) (int, error) {
	return r.stream.Read(p)
}

func (r *StreamByteReader) CancelRead(code quic.StreamErrorCode) {
	r.stream.CancelRead(code)
}

func (r *StreamByteReader) ReadByte() (byte, error) {
	buf := [1]byte{0}
	_, err := r.stream.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), channelType, maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, nil)
	c.channelsManager.addChannel(channel)
	return channel, nil
}

func (c *Conversation) OpenUDPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

func (c *Conversation) OpenTCPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-tcp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}
func (c *Conversation) RequestTCPReverseChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildRequestReverseChannelAdditionalBytes(localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "request-reverse-tcp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil

}
func (c *Conversation) RequestUDPReverseChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildRequestReverseChannelAdditionalBytes(localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "request-reverse-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, LocalAddr: localAddr, RemoteAddr: remoteAddr}, nil

}
// OpenTCPReverseForwardingChannel opens a server-initiated data channel
// for one inbound connection on a previously-established reverse-TCP
// forward.  bindAddr is the server-side listening address that produced
// the connection: it is serialised into the channel-header additional
// bytes so the client-side dispatcher can route the channel to the
// matching reverse-forward handler.  Without this, multiple concurrent
// reverse-TCP forwards on the same conversation would be indistinguishable
// to the client and would race over each other.
func (c *Conversation) OpenTCPReverseForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, bindAddr *net.TCPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildForwardingChannelAdditionalBytes(bindAddr.IP, uint16(bindAddr.Port))
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "open-request-reverse-tcp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPOpenReverseForwardingChannelImpl{Channel: channel, BindAddr: bindAddr}, nil
}

// OpenUDPReverseForwardingChannel is the UDP analogue of
// OpenTCPReverseForwardingChannel; see its doc for the role of bindAddr.
//
// Pre-existing PR #148 versions of this function encoded the addresses in
// the channel-type string itself ("open-request-reverse-udp,<local>,<remote>")
// because the additional-bytes path was not wired up.  We now use the
// regular additional-bytes header for one address (the bind side), which
// keeps the wire format consistent with the TCP variant and lets the
// client dispatcher reuse the same parser.
func (c *Conversation) OpenUDPReverseForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, bindAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildForwardingChannelAdditionalBytes(bindAddr.IP, uint16(bindAddr.Port))
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "open-request-reverse-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPOpenReverseForwardingChannelImpl{Channel: channel, BindAddr: bindAddr}, nil
}


func (c *Conversation) AcceptChannel(ctx context.Context) (Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			c.channelsManager.addChannel(channel)
			return channel, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.channelsAcceptQueue.Chan():
		}
	}

}

// blocks until the datagram is added
// the first field must be the channel ID
func (c *Conversation) AddDatagram(ctx context.Context, datagram []byte) error {
	buf := &util.BytesReadCloser{Reader: bytes.NewReader(datagram)}
	channelID, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	channel, ok := c.channelsManager.getChannel(channelID)
	if !ok {
		dgramQueue := util.NewDatagramsQueue(10)
		dgramQueue.Add(datagram[buf.Size()-int64(buf.Len()):])
		c.channelsManager.addDanglingDatagramsQueue(channelID, dgramQueue)
		return util.ChannelNotFound{ChannelID: channelID}
	}
	return channel.waitAddDatagram(ctx, datagram[buf.Size()-int64(buf.Len()):])
}

func (c *Conversation) Close() {
	c.controlStream.Close()
	c.cancelContext(nil)
}

func (c *Conversation) Context() context.Context {
	return c.context
}

func (c *Conversation) getDatagramSenderForChannel(channelID util.ChannelID) func(datagram []byte) error {
	return func(datagram []byte) error {
		buf := util.AppendVarInt(nil, uint64(c.controlStream.StreamID()))
		buf = util.AppendVarInt(buf, channelID)
		buf = append(buf, datagram...)
		return c.messageSender.SendDatagram(buf)
	}
}

func (c *Conversation) ConversationID() ConversationID {
	return c.conversationID
}
