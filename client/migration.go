package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/francoismichel/ssh3/client/netchange"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// StartMigration wires the netlink-based network-change watcher into
// a QUIC connection-migration coordinator running for the lifetime of
// the connection.
//
// The coordinator does, for every detected network change:
//
//  1. Open a fresh UDP socket and wrap it in a *quic.Transport.
//  2. Ask quic-go to add this transport as a candidate path on the
//     connection (Conn.AddPath).
//  3. Probe the path (PATH_CHALLENGE / PATH_RESPONSE) with a 5 s
//     timeout.
//  4. If the probe succeeds, switch the active path to the new one
//     and remember the new transport on the Client.  The previous
//     candidate transport (if any) is closed at this point - we keep
//     exactly one "old" transport alive past a switch so that any
//     in-flight packets still being sent over it can drain before we
//     yank the socket out from under quic-go.
//  5. If the probe fails, abandon: close the new path, the new
//     transport, and the new UDP socket; log a warning; continue.
//
// While a migration is in-flight, subsequent network-change events
// are coalesced: the coordinator simply notes that "another change
// happened" and re-evaluates as soon as the current migration ends.
// We never run two migrations concurrently.
//
// startMigrationLoop returns immediately; the goroutine it spawns
// stops when ctx is cancelled or when the netchange watcher errors
// out.  Errors are logged, not returned, because the goroutine
// outlives the call.
func (c *Client) StartMigration(ctx context.Context) {
	if c.qtransport == nil {
		// No transport handle - we cannot migrate.  This is the
		// proxy-jump path; not an error.
		return
	}

	watcher, err := netchange.New()
	if err != nil {
		if errors.Is(err, netchange.ErrUnsupported) {
			log.Info().Msg("connection migration disabled: netchange watcher not supported on this platform")
		} else {
			log.Warn().Msgf("connection migration disabled: %s", err)
		}
		return
	}

	mc := &migrationCoordinator{
		client:  c,
		watcher: watcher,
	}
	go mc.run(ctx)
}

// migrationCoordinator owns the goroutine that reacts to
// netchange.Watcher events and drives quic-go's path migration API.
type migrationCoordinator struct {
	client  *Client
	watcher netchange.Watcher

	// mu protects busy / pending and serialises mutation of the
	// transport pointers below.
	mu sync.Mutex
	// busy is true while a migrate() call is in progress.  While
	// busy, additional events do NOT trigger a parallel migration:
	// they just set pending = true so the in-flight migration knows
	// to do one more cycle when it finishes.  This is the coalescing
	// the package comment promises - implemented inside the
	// coordinator rather than relying on the netchange watcher's
	// debounce alone.
	busy    bool
	pending bool
	// previousTransport is the transport that owned the path active
	// before the most recent successful Switch.  It is kept alive
	// across one migration so that quic-go can drain any in-flight
	// packets, and closed at the next successful Switch.  nil before
	// the first migration.
	previousTransport *quic.Transport
}

func (mc *migrationCoordinator) run(ctx context.Context) {
	defer func() {
		if mc.watcher != nil {
			if err := mc.watcher.Close(); err != nil {
				log.Debug().Msgf("migration: closing netchange watcher: %s", err)
			}
		}
		if mc.previousTransport != nil {
			_ = mc.previousTransport.Close()
		}
	}()

	connDone := mc.client.qconn.Context().Done()

	// Auto-restart loop for the netchange watcher.  A transient
	// kernel error (ENOBUFS under netlink pressure, a momentary
	// read failure) closes the events channel and exits the inner
	// for-loop; we then back off, reopen the watcher and resume.
	// Without this loop one such hiccup permanently disabled
	// migration for the rest of the connection's lifetime - a
	// silent-degradation mode flagged by the audit.
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		mc.consumeEvents(ctx, connDone)

		// consumeEvents returns either because the events channel
		// closed (watcher died) or because ctx / qconn ended.  In
		// the latter case we exit; in the former we try to reopen.
		select {
		case <-ctx.Done():
			return
		case <-connDone:
			return
		default:
		}

		log.Warn().Msgf("migration: netchange watcher died, reopening in %s", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		case <-connDone:
			return
		}
		newWatcher, err := netchange.New()
		if err != nil {
			log.Warn().Msgf("migration: could not reopen netchange watcher: %s", err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// Close the old (already-broken) watcher just in case it
		// still holds an fd, and swap in the new one.
		if mc.watcher != nil {
			_ = mc.watcher.Close()
		}
		mc.watcher = newWatcher
		backoff = 500 * time.Millisecond
		log.Info().Msg("migration: netchange watcher reopened")
	}
}

// consumeEvents reads from the current watcher's Events channel until
// either the channel closes (watcher error) or one of the cancellation
// channels fires.  It does not own the watcher's lifetime - the outer
// run() decides whether to reopen or shut down.
func (mc *migrationCoordinator) consumeEvents(ctx context.Context, connDone <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-connDone:
			return
		case ev, ok := <-mc.watcher.Events():
			if !ok {
				log.Debug().Msg("migration: netchange events channel closed")
				return
			}
			mc.handleEvent(ctx, ev)
		}
	}
}

// handleEvent either starts a fresh migration cycle or records that
// "another change happened" if a cycle is already running.  In the
// latter case the in-flight cycle will run one additional migration
// after it finishes, coalescing all the bursty events that arrived
// while it was busy into a single follow-up.
func (mc *migrationCoordinator) handleEvent(ctx context.Context, ev netchange.Event) {
	mc.mu.Lock()
	if mc.busy {
		mc.pending = true
		mc.mu.Unlock()
		log.Debug().Msgf("migration: queued network change (%s); migrate in progress", ev.Reason)
		return
	}
	mc.busy = true
	mc.mu.Unlock()

	for {
		log.Info().Msgf("migration: network change observed (%s), attempting path migration", ev.Reason)
		if err := mc.migrate(ctx); err != nil {
			log.Warn().Msgf("migration: %s", err)
		} else {
			log.Info().Msg("migration: switched to new network path successfully")
		}

		// Check whether more events arrived while we were busy.
		// If so, do one more cycle - but only one, regardless of
		// how many events piled up.  All of them collapse to a
		// single follow-up migration because by the time we get
		// here, the latest network state is what matters; the
		// individual reasons are no longer interesting.
		mc.mu.Lock()
		if !mc.pending {
			mc.busy = false
			mc.mu.Unlock()
			return
		}
		mc.pending = false
		mc.mu.Unlock()
		ev = netchange.Event{When: time.Now(), Reason: "coalesced-follow-up"}
	}
}

// migrate runs one full probe-and-switch cycle.  Returns nil on
// success or a descriptive error on failure (in which case the new
// transport/socket are already cleaned up).
func (mc *migrationCoordinator) migrate(ctx context.Context) error {
	// Open a fresh UDP socket.  Letting the kernel pick the local
	// address means we automatically use the new default route.
	udpConn, err := net.ListenUDP(udpNetworkFor(mc.client.qconn), nil)
	if err != nil {
		return fmt.Errorf("open new UDP socket: %w", err)
	}

	newTransport := &quic.Transport{Conn: udpConn}

	// AddPath registers the new transport with quic-go and gives us
	// back a *quic.Path we can probe and switch onto.
	path, err := mc.client.qconn.AddPath(newTransport)
	if err != nil {
		_ = newTransport.Close()
		_ = udpConn.Close()
		return fmt.Errorf("add path: %w", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := path.Probe(probeCtx); err != nil {
		_ = path.Close()
		_ = newTransport.Close()
		_ = udpConn.Close()
		return fmt.Errorf("probe new path: %w", err)
	}

	if err := path.Switch(); err != nil {
		_ = path.Close()
		_ = newTransport.Close()
		_ = udpConn.Close()
		return fmt.Errorf("switch to new path: %w", err)
	}

	// Migration succeeded.  Retire the previous candidate transport
	// (the one we promoted last time round) and keep the just-
	// retired transport in its slot.  We keep one generation of
	// "old" transport alive so quic-go has time to drain in-flight
	// packets on it before the socket disappears.
	oldTransport := mc.client.qtransport
	if mc.previousTransport != nil {
		if err := mc.previousTransport.Close(); err != nil {
			log.Debug().Msgf("migration: closing retired previous transport: %s", err)
		}
	}
	mc.previousTransport = oldTransport
	mc.client.qtransport = newTransport
	return nil
}

// udpNetworkFor picks "udp4" / "udp6" matching the address family of
// the connection's current remote endpoint, so the new socket lands
// in the right family.
func udpNetworkFor(conn *quic.Conn) string {
	// RemoteAddr is a *net.UDPAddr on quic-go's *quic.Conn for the
	// dialed (client) case.
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && addr != nil {
		if addr.IP.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return "udp"
}
