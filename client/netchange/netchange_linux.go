//go:build linux

package netchange

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxWatcher is the Linux netlink-backed implementation of Watcher.
//
// It opens an AF_NETLINK / NETLINK_ROUTE socket subscribed to the
// address, route and link multicast groups, reads kernel notifications
// in a background goroutine, debounces bursts of messages with a 250 ms
// timer, and forwards a single coarse Event per burst on the Events
// channel.
//
// To make the read loop cleanly interruptible by Close, the netlink
// socket is set to non-blocking and the goroutine waits on Poll with
// two file descriptors: the netlink socket and the read end of a
// self-pipe.  Close writes one byte to the pipe to wake the poll;
// merely closing the netlink fd is not a reliable wake-up on Linux
// (recvfrom on a netlink socket does not always return EBADF when the
// fd is closed by another thread).
type linuxWatcher struct {
	fd     int
	wakeR  int // read end of the wake pipe, polled alongside fd
	wakeW  int // write end of the wake pipe, written by Close
	events chan Event

	// closeOnce makes Close idempotent.  closeErr is the error
	// returned by the first call (subsequent calls return the same
	// value).
	closeOnce sync.Once
	closeErr  error

	// wg waits for the background reader goroutine to exit before
	// Close returns, so the events channel is fully drained and the
	// fd is fully released by the time Close hands control back.
	wg sync.WaitGroup
}

// New constructs a Watcher appropriate for the current platform.  On
// Linux it opens a NETLINK_ROUTE socket and subscribes to the relevant
// multicast groups.
func New() (Watcher, error) {
	fd, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE |
			unix.RTMGRP_IPV6_ROUTE |
			unix.RTMGRP_LINK,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Self-pipe used to interrupt poll() from Close.  O_CLOEXEC
	// matches the rest of the project's fd hygiene.
	var pipefds [2]int
	if err := unix.Pipe2(pipefds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, err
	}
	w := &linuxWatcher{
		fd:     fd,
		wakeR:  pipefds[0],
		wakeW:  pipefds[1],
		events: make(chan Event, eventsBuffer),
	}
	w.wg.Add(1)
	go w.run()
	return w, nil
}

// Events implements Watcher.
func (w *linuxWatcher) Events() <-chan Event {
	return w.events
}

// Close implements Watcher.  It is idempotent: subsequent calls return
// the same error (or nil) without acting again.
func (w *linuxWatcher) Close() error {
	w.closeOnce.Do(func() {
		// Wake the poll() in the read loop.  A single byte is
		// enough; the reader doesn't even bother to read it,
		// since detecting POLLIN on wakeR is itself the signal.
		var b [1]byte
		_, _ = unix.Write(w.wakeW, b[:])
		// Wait for the goroutine to exit before tearing down
		// fds, so we don't close fds out from under an in-flight
		// syscall.
		w.wg.Wait()

		// Close fds; record the first non-nil error.
		if err := unix.Close(w.fd); err != nil {
			w.closeErr = err
		}
		w.fd = -1
		if err := unix.Close(w.wakeR); err != nil && w.closeErr == nil {
			w.closeErr = err
		}
		w.wakeR = -1
		if err := unix.Close(w.wakeW); err != nil && w.closeErr == nil {
			w.closeErr = err
		}
		w.wakeW = -1
	})
	return w.closeErr
}

// familySuffix turns a netlink address family byte (AF_INET / AF_INET6)
// into "4" or "6".  Unknown families fall back to "" so the caller can
// emit a family-agnostic reason.
func familySuffix(family byte) string {
	switch family {
	case unix.AF_INET:
		return "4"
	case unix.AF_INET6:
		return "6"
	default:
		return ""
	}
}

// reasonFor maps a netlink message header + body to a coarse Reason
// string, or returns "" if the message is not interesting to us.  For
// RTM_*ADDR and RTM_*ROUTE the first byte of the body is the address
// family (ifaddrmsg.ifa_family / rtmsg.rtm_family); parsing only that
// byte is enough to distinguish v4 from v6 without pulling in a full
// netlink attribute parser.
func reasonFor(msgType uint16, body []byte) string {
	switch msgType {
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		suf := ""
		if len(body) > 0 {
			suf = familySuffix(body[0])
		}
		if suf == "" {
			return "ip-addr-change"
		}
		return "ipv" + suf + "-addr-change"
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		suf := ""
		if len(body) > 0 {
			suf = familySuffix(body[0])
		}
		if suf == "" {
			return "ip-route-change"
		}
		return "ipv" + suf + "-route-change"
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		return "link-change"
	default:
		return ""
	}
}

// run is the background reader goroutine.  It owns the events channel
// (it is the only writer and the only closer) and exits on the first
// non-recoverable read error or when Close is signalled via the
// self-pipe.
func (w *linuxWatcher) run() {
	defer w.wg.Done()
	defer close(w.events)

	buf := make([]byte, 65536)

	var (
		timer       *time.Timer
		timerActive bool
		lastReason  string
	)
	// timerExpires returns a channel that fires when the debounce
	// window elapses, or nil if no debounce is in flight.  Using a
	// helper keeps the main select readable.
	timerExpires := func() <-chan time.Time {
		if !timerActive {
			return nil
		}
		return timer.C
	}
	// armTimer (re)starts the debounce window.
	armTimer := func() {
		if timer == nil {
			timer = time.NewTimer(debounceInterval)
		} else {
			if timerActive && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(debounceInterval)
		}
		timerActive = true
	}

	// pollWait blocks until either the netlink socket is readable or
	// the wake pipe is readable.  Returns (sockReady, woken, err).
	// We use a small ad-hoc helper rather than dragging in the
	// runtime poller because the socket already lives outside Go's
	// netpoller and we want full control over wake-up semantics.
	pollWait := func(timeoutMs int) (bool, bool, error) {
		pfds := []unix.PollFd{
			{Fd: int32(w.fd), Events: unix.POLLIN},
			{Fd: int32(w.wakeR), Events: unix.POLLIN},
		}
		for {
			_, err := unix.Poll(pfds, timeoutMs)
			if err == unix.EINTR {
				// Restart on signal interruption.
				continue
			}
			if err != nil {
				return false, false, err
			}
			sockReady := pfds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0
			woken := pfds[1].Revents&unix.POLLIN != 0
			return sockReady, woken, nil
		}
	}

	// processReadable drains the netlink socket of any pending
	// messages and returns the most recent interesting Reason (or
	// "" if none).  Non-blocking reads return EAGAIN once the queue
	// is empty.
	processReadable := func() (string, error) {
		var reason string
		for {
			n, _, err := unix.Recvfrom(w.fd, buf, unix.MSG_DONTWAIT)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return reason, nil
			}
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return reason, err
			}
			data := buf[:n]
			for len(data) >= unix.NLMSG_HDRLEN {
				h := (*unix.NlMsghdr)(unsafe.Pointer(&data[0]))
				if int(h.Len) < unix.NLMSG_HDRLEN || int(h.Len) > len(data) {
					break
				}
				bodyStart := unix.NLMSG_HDRLEN
				bodyEnd := int(h.Len)
				var body []byte
				if bodyEnd > bodyStart && bodyEnd <= len(data) {
					body = data[bodyStart:bodyEnd]
				}
				if r := reasonFor(h.Type, body); r != "" {
					reason = r
				}
				step := (int(h.Len) + 3) &^ 3
				if step > len(data) {
					break
				}
				data = data[step:]
			}
		}
	}

	for {
		// If a debounce is in flight, poll with a bounded timeout
		// so the fire-the-event branch below can run on time.
		timeoutMs := -1
		if timerActive {
			// Cap the poll wait so we re-check the timer.
			// time.AfterFunc would also work but this keeps
			// all wake-ups going through a single poll(),
			// which is easier to reason about.
			timeoutMs = int(debounceInterval / time.Millisecond)
		}
		sockReady, woken, err := pollWait(timeoutMs)
		if err != nil {
			// Non-recoverable: caller can construct a new
			// watcher if it wants to retry.
			return
		}
		if woken {
			// Close was called.  Drain the pipe (best effort)
			// and exit.
			var drain [8]byte
			_, _ = unix.Read(w.wakeR, drain[:])
			return
		}
		if sockReady {
			r, rerr := processReadable()
			if rerr != nil {
				return
			}
			if r != "" {
				lastReason = r
				armTimer()
			}
		}
		// Check the debounce timer; the poll timeout above
		// guarantees we get here at least every debounceInterval
		// while a debounce is in flight.
		select {
		case <-timerExpires():
			ev := Event{When: time.Now(), Reason: lastReason}
			select {
			case w.events <- ev:
			default:
			}
			timerActive = false
		default:
		}
	}
}
