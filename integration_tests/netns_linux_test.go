//go:build linux

package integration_tests

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// netnsEnv builds a three-namespace topology for the proxy-jump
// migration integration test.  Replaces the previous two-veth-pair-
// over-loopback-with-DNAT design, which left target-conversation
// datagram routing ambiguous and never converged in the test loop.
//
// Topology:
//
//	client_ns                host                  proxy_ns          target_ns
//	  ┌─────────┐  vethCA   ┌──────┐  vethP        ┌─────────┐  vethT  ┌─────────┐
//	  │ client  ├──────────►│      ├──────────────►│  proxy  ├────────►│ target  │
//	  │ (.2)    │  vethCB   │ host │   10.99.1.0/30│  server │  10.99. │ server  │
//	  │         ├──────────►│      │   .1 ↔ .2     │  (.2)   │  2.0/30 │ (.2)    │
//	  └─────────┘           └──────┘                └─────────┘  .1↔.2 └─────────┘
//	  10.99.0.0/30  pair A                                                ▲
//	  10.99.0.4/30  pair B (route swap target)                            │
//
// Subnets (host is .1 on each; the inner end is .2 or .6):
//
//	pair A   10.99.0.0/30      host vethCAOuter (.1)  ↔  client_ns vethCAInner (.2)
//	pair B   10.99.0.4/30      host vethCBOuter (.5)  ↔  client_ns vethCBInner (.6)
//	pair P   10.99.1.0/30      host vethPOuter  (.1)  ↔  proxy_ns  vethPInner  (.2)
//	pair T   10.99.2.0/30      proxy_ns vethTOuter (.1) ↔ target_ns vethTInner (.2)
//
// Routing:
//
//	host       net.ipv4.ip_forward=1.  Routes to proxy_ns subnet via vethPOuter;
//	           routes to target_ns subnet via proxy_ns IP (10.99.1.2) over vethPOuter.
//	client_ns  default route via 10.99.0.1 initially (pair A);
//	           swapDefaultRoute() flips it to 10.99.0.5 (pair B) - this is the
//	           synthetic "network change" event the migration coordinator reacts to.
//	proxy_ns   net.ipv4.ip_forward=1; default route via host (10.99.1.1);
//	           routes to target subnet via target_ns IP (10.99.2.2) over vethTOuter.
//	target_ns  default route via 10.99.2.1 (proxy_ns).
//
// No DNAT, no route_localnet, no loopback overloading anywhere - the
// proxy server binds a routable address in proxy_ns and the target
// server binds a routable address in target_ns.  The client talks
// to the proxy through the host; the proxy talks to the target
// through the proxy↔target veth.  When the route swap fires inside
// client_ns, the *only* socket whose source IP changes is the
// client↔host one, i.e. the proxy leg of the QUIC tunnel.  The
// target leg is invisible to the swap (proxy↔target subnet is
// untouched).
type netnsEnv struct {
	clientNS string
	proxyNS  string
	targetNS string

	// Pair A: host ↔ client_ns (initial default route inside client_ns).
	vethCAOuter   string
	vethCAInner   string
	vethCAOuterIP string // 10.99.0.1
	vethCAInnerIP string // 10.99.0.2

	// Pair B: host ↔ client_ns (route swap target).
	vethCBOuter   string
	vethCBInner   string
	vethCBOuterIP string // 10.99.0.5
	vethCBInnerIP string // 10.99.0.6

	// Pair P: host ↔ proxy_ns.
	vethPOuter   string
	vethPInner   string
	vethPOuterIP string // 10.99.1.1
	vethPInnerIP string // 10.99.1.2

	// Pair T: proxy_ns ↔ target_ns.  vethTOuter lives in proxy_ns,
	// vethTInner in target_ns; neither sees the host.
	vethTOuter   string
	vethTInner   string
	vethTOuterIP string // 10.99.2.1
	vethTInnerIP string // 10.99.2.2

	// Host sysctls we flip and must restore.  Keyed by /proc/sys path.
	sysctlSaved map[string]string

	// Cleanup state.  Each item is the inverse command (with args) to
	// undo a setup step; teardown drains the slice in LIFO order.
	cleanups []func() error
}

// randomSuffix yields a short hex tag that, combined with PID, keeps
// netns / veth names unique across reruns and concurrent test packages
// without colliding against the 15-byte ifname limit.
func randomSuffix() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Falls back to PID if /dev/urandom fails, which is good
		// enough for uniqueness within one run.
		return fmt.Sprintf("%06x", os.Getpid()&0xffffff)
	}
	return hex.EncodeToString(b[:])
}

// newNetnsEnv allocates names but does NOT touch the network yet.  The
// caller invokes setup() afterwards so we can return setup errors with
// proper context.
func newNetnsEnv() *netnsEnv {
	tag := randomSuffix()
	// Linux ifname max 15 bytes.  Our longest prefix is "vmgrp-" + 6
	// hex + "-o" = 14 bytes; we keep all names short to stay under.
	return &netnsEnv{
		clientNS: fmt.Sprintf("ssh3mig-c-%s", tag),
		proxyNS:  fmt.Sprintf("ssh3mig-p-%s", tag),
		targetNS: fmt.Sprintf("ssh3mig-t-%s", tag),

		vethCAOuter: fmt.Sprintf("vca-%s-o", tag),
		vethCAInner: fmt.Sprintf("vca-%s-i", tag),
		vethCBOuter: fmt.Sprintf("vcb-%s-o", tag),
		vethCBInner: fmt.Sprintf("vcb-%s-i", tag),
		vethPOuter:  fmt.Sprintf("vpx-%s-o", tag),
		vethPInner:  fmt.Sprintf("vpx-%s-i", tag),
		vethTOuter:  fmt.Sprintf("vtg-%s-o", tag),
		vethTInner:  fmt.Sprintf("vtg-%s-i", tag),

		vethCAOuterIP: "10.99.0.1",
		vethCAInnerIP: "10.99.0.2",
		vethCBOuterIP: "10.99.0.5",
		vethCBInnerIP: "10.99.0.6",
		vethPOuterIP:  "10.99.1.1",
		vethPInnerIP:  "10.99.1.2",
		vethTOuterIP:  "10.99.2.1",
		vethTInnerIP:  "10.99.2.2",

		sysctlSaved: make(map[string]string),
	}
}

// run shells out to a command and returns its combined output along
// with a wrapped error that includes the original command and stderr -
// crucial for figuring out which `ip` invocation broke when the test
// fails.
func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err,
			strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ipnetns runs `ip netns exec <ns> <cmd...>` and returns the same
// detailed error as run().
func (e *netnsEnv) ipnetns(ns string, args ...string) (string, error) {
	full := append([]string{"netns", "exec", ns}, args...)
	return run("ip", full...)
}

// addCleanup pushes an undo step on the LIFO stack; teardown will drain
// it even on test failure.
func (e *netnsEnv) addCleanup(f func() error) {
	e.cleanups = append(e.cleanups, f)
}

// saveAndSetSysctl reads the current value of /proc/sys path, stashes
// it for teardown, then writes value.
func (e *netnsEnv) saveAndSetSysctl(path, value string) error {
	prev, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	e.sysctlSaved[path] = strings.TrimSpace(string(prev))
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// setup builds the whole topology.  Returns the first error
// encountered; the caller MUST still call teardown() afterwards to undo
// any partial state.
func (e *netnsEnv) setup() error {
	// 1. Create three namespaces.  Probe support BEFORE touching
	//    anything else so the skip reason is clean.
	for _, ns := range []string{e.clientNS, e.proxyNS, e.targetNS} {
		if out, err := run("ip", "netns", "add", ns); err != nil {
			return fmt.Errorf("ip netns add %s (kernel may lack netns support, or insufficient privilege): %w (output: %s)", ns, err, out)
		}
		nsCopy := ns
		e.addCleanup(func() error {
			_, err := run("ip", "netns", "del", nsCopy)
			return err
		})
		// Bring lo up inside each namespace.  Loopback is a hard
		// prerequisite for almost anything userspace does, including
		// quic-go's own sockets binding to wildcard ::.
		if _, err := e.ipnetns(ns, "ip", "link", "set", "lo", "up"); err != nil {
			return err
		}
	}

	// 2. Create veth pairs.  Deleting the outer side removes the inner
	//    side too, so cleanup only undoes the outer.
	pairs := []struct {
		outer string
		inner string
	}{
		{e.vethCAOuter, e.vethCAInner},
		{e.vethCBOuter, e.vethCBInner},
		{e.vethPOuter, e.vethPInner},
		{e.vethTOuter, e.vethTInner},
	}
	for _, p := range pairs {
		if _, err := run("ip", "link", "add", p.outer, "type", "veth", "peer", "name", p.inner); err != nil {
			return err
		}
		outerCopy := p.outer
		e.addCleanup(func() error {
			_, err := run("ip", "link", "del", outerCopy)
			return err
		})
	}

	// 3. Push the inner ends into the right namespaces.  vethT's
	//    "outer" lives in proxy_ns - it has no host-side leg.
	moves := []struct {
		iface string
		ns    string
	}{
		{e.vethCAInner, e.clientNS},
		{e.vethCBInner, e.clientNS},
		{e.vethPInner, e.proxyNS},
		{e.vethTOuter, e.proxyNS},
		{e.vethTInner, e.targetNS},
	}
	for _, m := range moves {
		if _, err := run("ip", "link", "set", m.iface, "netns", m.ns); err != nil {
			return err
		}
	}

	// 4. Address the host-side legs (pair A/B/P).
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethCAOuterIP + "/30", "dev", e.vethCAOuter},
		{"ip", "addr", "add", e.vethCBOuterIP + "/30", "dev", e.vethCBOuter},
		{"ip", "addr", "add", e.vethPOuterIP + "/30", "dev", e.vethPOuter},
		{"ip", "link", "set", e.vethCAOuter, "up"},
		{"ip", "link", "set", e.vethCBOuter, "up"},
		{"ip", "link", "set", e.vethPOuter, "up"},
	} {
		if _, err := run(step[0], step[1:]...); err != nil {
			return err
		}
	}

	// 5. Address client_ns interfaces; install initial default route via pair A.
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethCAInnerIP + "/30", "dev", e.vethCAInner},
		{"ip", "addr", "add", e.vethCBInnerIP + "/30", "dev", e.vethCBInner},
		{"ip", "link", "set", e.vethCAInner, "up"},
		{"ip", "link", "set", e.vethCBInner, "up"},
		{"ip", "route", "add", "default", "via", e.vethCAOuterIP},
	} {
		if _, err := e.ipnetns(e.clientNS, step...); err != nil {
			return err
		}
	}

	// 6. Address proxy_ns interfaces.  proxy_ns connects to the host
	//    on pair P (its default route) and to target_ns on pair T.
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethPInnerIP + "/30", "dev", e.vethPInner},
		{"ip", "addr", "add", e.vethTOuterIP + "/30", "dev", e.vethTOuter},
		{"ip", "link", "set", e.vethPInner, "up"},
		{"ip", "link", "set", e.vethTOuter, "up"},
		{"ip", "route", "add", "default", "via", e.vethPOuterIP},
	} {
		if _, err := e.ipnetns(e.proxyNS, step...); err != nil {
			return err
		}
	}

	// 7. Address target_ns interfaces.  target_ns reaches everything
	//    through proxy_ns.
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethTInnerIP + "/30", "dev", e.vethTInner},
		{"ip", "link", "set", e.vethTInner, "up"},
		{"ip", "route", "add", "default", "via", e.vethTOuterIP},
	} {
		if _, err := e.ipnetns(e.targetNS, step...); err != nil {
			return err
		}
	}

	// 8. Enable IP forwarding on the host (so client_ns ↔ proxy_ns
	//    traffic can transit) and inside proxy_ns (so the target leg
	//    can transit when the proxy itself doesn't terminate).  The
	//    proxy *does* terminate the primary QUIC connection so the
	//    inner forwarding is not strictly required for the QUIC path,
	//    but the test's reverse-TCP origin server lives on the host
	//    and the client's reverse-forward dial back to it goes
	//    through the proxy via QUIC, so the IPv4 forwarding state
	//    here is the right belt-and-suspenders.
	if err := e.saveAndSetSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	e.addCleanup(func() error {
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(e.sysctlSaved["/proc/sys/net/ipv4/ip_forward"]), 0644)
	})

	// 9. Host needs to know how to reach the target_ns subnet
	//    (10.99.2.0/30) - it sits behind proxy_ns, so route via the
	//    proxy_ns address on pair P.
	if _, err := run("ip", "route", "add", "10.99.2.0/30", "via", e.vethPInnerIP); err != nil {
		return err
	}
	e.addCleanup(func() error {
		_, err := run("ip", "route", "del", "10.99.2.0/30")
		return err
	})

	// 10. Open the host's FORWARD chain for our private subnet block.
	//     Many modern distros (CachyOS, docker installs, firewalld)
	//     default to FORWARD policy DROP, which would silently drop
	//     every client_ns → proxy_ns and target_ns return packet and
	//     leave us with "QUIC handshake timeout" with no useful
	//     diagnostic.  -I (insert at top) jumps ACCEPT before any
	//     default-deny rule.
	for _, rule := range [][]string{
		{"-s", "10.99.0.0/16", "-d", "10.99.0.0/16", "-j", "ACCEPT"},
	} {
		insertArgs := append([]string{"-I", "FORWARD", "1"}, rule...)
		if _, err := run("iptables", insertArgs...); err != nil {
			return err
		}
		deleteArgs := append([]string{"-D", "FORWARD"}, rule...)
		e.addCleanup(func() error {
			_, err := run("iptables", deleteArgs...)
			return err
		})
	}

	return nil
}

// swapDefaultRoute moves the default route inside client_ns from pair A
// to pair B.  This is the synthetic "network change" event that
// triggers the migration coordinator: a new source-IP selection plus a
// netlink RTM_DELROUTE/RTM_NEWROUTE pair lands on the client's
// netchange watcher.
func (e *netnsEnv) swapDefaultRoute() error {
	if _, err := e.ipnetns(e.clientNS, "ip", "route", "del", "default", "via", e.vethCAOuterIP); err != nil {
		return err
	}
	if _, err := e.ipnetns(e.clientNS, "ip", "route", "add", "default", "via", e.vethCBOuterIP); err != nil {
		return err
	}
	return nil
}

// teardown undoes everything setup() did, in LIFO order.  Returns the
// first error but always attempts every step so leftover state does not
// poison subsequent runs.
func (e *netnsEnv) teardown() error {
	var firstErr error
	for i := len(e.cleanups) - 1; i >= 0; i-- {
		if err := e.cleanups[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	e.cleanups = nil
	return firstErr
}
