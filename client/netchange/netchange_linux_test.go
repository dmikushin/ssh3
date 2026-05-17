//go:build linux

package netchange

import (
	"errors"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestWatcherReceivesAddrChange triggers a synthetic netlink notification
// by adding (and then removing) a dummy IPv4 alias on the loopback
// interface, and verifies that the watcher emits an Event within one
// second.
//
// The test is skipped automatically when prerequisites aren't met,
// rather than gated by an environment variable, so it is safe to run
// in CI sandboxes:
//
//   - if the process cannot open an AF_NETLINK socket (typical for
//     locked-down CI containers), New() will fail and we skip;
//   - if the `ip` binary is missing from PATH, we skip;
//   - if `ip addr add` fails (e.g. the test runs as a non-root user
//     without CAP_NET_ADMIN), we skip rather than fail.
//
// On a developer workstation running as root this exercises the full
// path: socket open, multicast subscription, kernel notification,
// debounce, channel send.
func TestWatcherReceivesAddrChange(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 'ip' binary not found in PATH; skipping")
	}

	w, err := New()
	if err != nil {
		// EPERM / EACCES on a netlink socket is the canonical CI
		// sandbox signature.  Skip rather than fail.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("cannot open netlink socket in this sandbox: %v", err)
		}
		t.Fatalf("New() failed: %v", err)
	}
	defer w.Close()

	const testAddr = "127.0.0.42/32"

	addCmd := exec.Command("ip", "addr", "add", testAddr, "dev", "lo")
	if out, err := addCmd.CombinedOutput(); err != nil {
		// Non-root or otherwise insufficient privilege: skip.
		t.Skipf("ip addr add failed (need root / CAP_NET_ADMIN?): %v: %s", err, string(out))
	}
	defer func() {
		// Best-effort cleanup; ignore errors so we don't mask a
		// real test failure with a cleanup failure.
		_ = exec.Command("ip", "addr", "del", testAddr, "dev", "lo").Run()
	}()

	select {
	case ev, ok := <-w.Events():
		if !ok {
			t.Fatal("Events channel closed unexpectedly")
		}
		if ev.Reason == "" {
			t.Fatalf("got event with empty Reason: %+v", ev)
		}
		if ev.When.IsZero() {
			t.Fatalf("got event with zero When: %+v", ev)
		}
		t.Logf("got event: %+v", ev)
	case <-time.After(1 * time.Second):
		t.Fatal("no Event received within 1s of ip addr add")
	}
}

// TestCloseIsIdempotent verifies that Close can be called multiple
// times without panicking, and that the Events channel ends up closed
// after the first call returns.
func TestCloseIsIdempotent(t *testing.T) {
	w, err := New()
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("cannot open netlink socket in this sandbox: %v", err)
		}
		t.Fatalf("New() failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close must not panic, must not block.
	_ = w.Close()

	// Channel must be closed after Close returns.
	select {
	case _, ok := <-w.Events():
		if ok {
			t.Fatal("Events channel still delivering after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Events channel not closed within 1s after Close")
	}
}

// TestReasonFor exercises the netlink-message-type-to-Reason mapping
// without touching the network.  This keeps the mapping locked down
// even when the integration test above has to skip.
func TestReasonFor(t *testing.T) {
	cases := []struct {
		name   string
		mtype  uint16
		body   []byte
		expect string
	}{
		{"newaddr-v4", unix.RTM_NEWADDR, []byte{unix.AF_INET}, "ipv4-addr-change"},
		{"deladdr-v6", unix.RTM_DELADDR, []byte{unix.AF_INET6}, "ipv6-addr-change"},
		{"newroute-v4", unix.RTM_NEWROUTE, []byte{unix.AF_INET}, "ipv4-route-change"},
		{"delroute-v6", unix.RTM_DELROUTE, []byte{unix.AF_INET6}, "ipv6-route-change"},
		{"newlink", unix.RTM_NEWLINK, nil, "link-change"},
		{"dellink", unix.RTM_DELLINK, nil, "link-change"},
		{"ignored-getaddr", unix.RTM_GETADDR, nil, ""},
		{"addr-empty-body", unix.RTM_NEWADDR, nil, "ip-addr-change"},
		{"route-empty-body", unix.RTM_NEWROUTE, nil, "ip-route-change"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reasonFor(c.mtype, c.body)
			if got != c.expect {
				t.Fatalf("reasonFor(%d, %v) = %q, want %q", c.mtype, c.body, got, c.expect)
			}
		})
	}
}
