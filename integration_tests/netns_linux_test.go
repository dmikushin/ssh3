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

// netnsEnv holds the names/IPs of the throw-away network namespace and
// veth pairs used by the migration integration test.  Two veth pairs
// connect the netns to the host so that a "route swap" inside the netns
// causes the QUIC client to pick a new source IP and trigger the
// netlink-driven migration coordinator.
//
// Topology:
//
//   host                                       netns (nsName)
//   ---------------------------------------    ----------------------------
//   vethAOuter  192.168.250.1/30   <-- veth --> vethAInner  192.168.250.2/30
//   vethBOuter  192.168.250.5/30   <-- veth --> vethBInner  192.168.250.6/30
//
// Inside the netns the default route initially goes via 192.168.250.1
// (host-side IP of pair A); flipping it to 192.168.250.5 (pair B) is
// what we use to fake a "network change" event for the migration
// coordinator inside the client.
//
// On the host, a DNAT rule rewrites incoming traffic on either host
// veth destined for the proxied service IP (chosen from the same /30
// range) to 127.0.0.1:4433 where the ssh3 test server actually listens.
// route_localnet=1 must be set on the host veth interfaces for the
// post-DNAT route lookup to send the packet to the loopback-bound
// listener.
type netnsEnv struct {
	nsName string

	// outer (host-side) interface names and IPs
	vethAOuter   string
	vethAInner   string
	vethAOuterIP string // 192.168.250.1
	vethAInnerIP string // 192.168.250.2

	vethBOuter   string
	vethBInner   string
	vethBOuterIP string // 192.168.250.5
	vethBInnerIP string // 192.168.250.6

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
	// Linux ifname max 15 bytes; "vma-" + 6 hex + "-i" = 13 bytes.
	return &netnsEnv{
		nsName:       fmt.Sprintf("ssh3mig-%s", tag),
		vethAOuter:   fmt.Sprintf("vma-%s-o", tag),
		vethAInner:   fmt.Sprintf("vma-%s-i", tag),
		vethAOuterIP: "192.168.250.1",
		vethAInnerIP: "192.168.250.2",
		vethBOuter:   fmt.Sprintf("vmb-%s-o", tag),
		vethBInner:   fmt.Sprintf("vmb-%s-i", tag),
		vethBOuterIP: "192.168.250.5",
		vethBInnerIP: "192.168.250.6",
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
func (e *netnsEnv) ipnetns(args ...string) (string, error) {
	full := append([]string{"netns", "exec", e.nsName}, args...)
	return run("ip", full...)
}

// addCleanup pushes an undo step on the LIFO stack; teardown will drain
// it even on test failure.
func (e *netnsEnv) addCleanup(f func() error) {
	e.cleanups = append(e.cleanups, f)
}

// setup builds the whole topology.  Returns the first error
// encountered; the caller MUST still call teardown() afterwards to undo
// any partial state.
func (e *netnsEnv) setup() error {
	// 1. Probe netns support BEFORE touching anything else.  If the
	//    kernel or the sandbox refuses, we want the cleanest possible
	//    "skip" signal.
	if out, err := run("ip", "netns", "add", e.nsName); err != nil {
		return fmt.Errorf("ip netns add (kernel may lack netns support, or insufficient privilege): %w (output: %s)", err, out)
	}
	e.addCleanup(func() error {
		_, err := run("ip", "netns", "del", e.nsName)
		return err
	})

	// 2. Create both veth pairs.  Deleting the outer side removes the
	//    inner side too, so cleanup only undoes the outer.
	if _, err := run("ip", "link", "add", e.vethAOuter, "type", "veth", "peer", "name", e.vethAInner); err != nil {
		return err
	}
	e.addCleanup(func() error {
		_, err := run("ip", "link", "del", e.vethAOuter)
		return err
	})
	if _, err := run("ip", "link", "add", e.vethBOuter, "type", "veth", "peer", "name", e.vethBInner); err != nil {
		return err
	}
	e.addCleanup(func() error {
		_, err := run("ip", "link", "del", e.vethBOuter)
		return err
	})

	// 3. Push the inner ends into the netns.
	if _, err := run("ip", "link", "set", e.vethAInner, "netns", e.nsName); err != nil {
		return err
	}
	if _, err := run("ip", "link", "set", e.vethBInner, "netns", e.nsName); err != nil {
		return err
	}

	// 4. Assign addresses + bring up everything.  Use /30 so each pair
	//    is its own little subnet; default route inside the netns picks
	//    which subnet leaves the namespace.
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethAOuterIP + "/30", "dev", e.vethAOuter},
		{"ip", "addr", "add", e.vethBOuterIP + "/30", "dev", e.vethBOuter},
		{"ip", "link", "set", e.vethAOuter, "up"},
		{"ip", "link", "set", e.vethBOuter, "up"},
	} {
		if _, err := run(step[0], step[1:]...); err != nil {
			return err
		}
	}
	for _, step := range [][]string{
		{"ip", "addr", "add", e.vethAInnerIP + "/30", "dev", e.vethAInner},
		{"ip", "addr", "add", e.vethBInnerIP + "/30", "dev", e.vethBInner},
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", e.vethAInner, "up"},
		{"ip", "link", "set", e.vethBInner, "up"},
		// Default route via pair A initially.
		{"ip", "route", "add", "default", "via", e.vethAOuterIP},
	} {
		if _, err := e.ipnetns(step...); err != nil {
			return err
		}
	}

	// 5. Allow loopback-bound services to receive packets that arrived
	//    on the host-side veths.  Without route_localnet the kernel
	//    drops martian packets (post-DNAT 127.0.0.1 destination on a
	//    non-loopback inbound interface).
	for _, iface := range []string{e.vethAOuter, e.vethBOuter} {
		if _, err := run("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", iface)); err != nil {
			return err
		}
	}

	// 6. DNAT every packet that comes in on either host veth and is
	//    destined to the server-side gateway IP at port 4433 onto the
	//    real loopback-bound server.  This is what lets the client
	//    inside the netns talk to 127.0.0.1:4433 on the host without
	//    us having to restart the server on a different bind address.
	//    We add a second rule for port 4444 (the proxy server) so the
	//    proxy-jump migration spec can reach both legs through the
	//    same gateway IPs.
	for _, dstIP := range []string{e.vethAOuterIP, e.vethBOuterIP} {
		for _, port := range []string{"4433", "4444"} {
			args := []string{"-t", "nat", "-A", "PREROUTING",
				"-p", "udp",
				"-d", dstIP,
				"--dport", port,
				"-j", "DNAT", "--to-destination", "127.0.0.1:" + port,
			}
			if _, err := run("iptables", args...); err != nil {
				return err
			}
			delArgs := append([]string{"-t", "nat", "-D", "PREROUTING"}, args[4:]...)
			// The cleanup deletes by spec, which iptables matches against
			// the rule we just inserted.
			e.addCleanup(func() error {
				_, err := run("iptables", delArgs...)
				return err
			})
		}
	}

	return nil
}

// swapDefaultRoute moves the default route inside the netns from pair A
// to pair B.  This is the synthetic "network change" event that
// triggers the migration coordinator: a new source-IP selection plus a
// netlink RTM_DELROUTE/RTM_NEWROUTE pair lands on the client's
// netchange watcher.
func (e *netnsEnv) swapDefaultRoute() error {
	if _, err := e.ipnetns("ip", "route", "del", "default", "via", e.vethAOuterIP); err != nil {
		return err
	}
	if _, err := e.ipnetns("ip", "route", "add", "default", "via", e.vethBOuterIP); err != nil {
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
