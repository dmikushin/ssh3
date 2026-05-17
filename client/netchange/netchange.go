// Package netchange provides a small, platform-independent watcher for
// operating-system level network changes (address changes, route changes,
// link state changes).  It is intended to feed a QUIC path migration
// coordinator: a single coarse "something changed" signal is enough to
// trigger a path re-evaluation, so this package deliberately does not
// attempt to classify the change beyond a short human-readable Reason.
package netchange

import (
	"errors"
	"time"
)

// Event is what the watcher emits on every detected network change.
// Keep it small on purpose -- the migration coordinator only needs to
// know "something changed, re-evaluate path".  We don't try to
// classify the kind of change inside this package.
type Event struct {
	// When the event was observed (time.Now() at debounce time).
	When time.Time
	// Reason is a short human-readable hint for logs, e.g.
	// "ipv4-addr-change", "ipv4-route-change", "link-change", ...
	// Consumers should not parse it; it's strictly for log messages.
	Reason string
}

// ErrUnsupported is returned by New on platforms where we don't have
// a real network watcher.
var ErrUnsupported = errors.New("netchange: not supported on this platform")

// Watcher delivers network-change events on a channel.  It is
// goroutine-safe (Events() can be read from multiple goroutines;
// Close() can be called from anywhere).  Closing the watcher closes
// the events channel.
type Watcher interface {
	// Events returns a channel that receives an event each time the
	// OS reports a relevant network state change.  Bursts of events
	// (e.g. ten kernel notifications when wlan0 hops to a new AP)
	// are debounced into a single emission.  The channel is never
	// closed until Close() is called.
	Events() <-chan Event
	// Close releases the underlying OS resources and stops the
	// background goroutine.  Idempotent.
	Close() error
}

// debounceInterval is the window over which a burst of kernel
// notifications is collapsed into a single Event.  Exposed as a
// package-private constant so the Linux implementation and any future
// platform back-end agree on the value.
const debounceInterval = 250 * time.Millisecond

// eventsBuffer is the capacity of the buffered Events channel.  Emission
// is non-blocking: if the consumer is slower than this, the newest event
// is dropped, because the consumer only needs the latest "something
// happened" signal, not a full history.
const eventsBuffer = 8
