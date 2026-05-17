package integration_tests

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var ssh3Path string
var ssh3ServerPath string

const DEFAULT_URL_PATH = "/ssh3-tests"
const DEFAULT_PROXY_URL_PATH = "/ssh3-tests-proxy"

var serverCommand *exec.Cmd
var serverSessions map[string]*Session = make(map[string]*Session) // bind address to session
var proxyServerCommand *exec.Cmd
var proxyServerSession *Session
var rsaPrivKeyPath string
var ed25519PrivKeyPath string
var ecdsaPrivKeyPath string
var attackerPrivKeyPath string
var username string
var ecdsaUsername string

const serverBind = "127.0.0.1:4433"
const proxyServerBind = "127.0.0.1:4444"

var oldServerBinds map[string]string = map[string]string{
	"v0.1.5-rc1": "127.0.0.1:5000",
	"v0.1.5-rc5": "127.0.0.1:5001",
} // tag version to bind string

func IPv6LoopbackAvailable(addrs []net.Addr) bool {
	for _, addr := range addrs {
		Expect(addr).To(BeAssignableToTypeOf(&net.IPNet{}))
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.To16() != nil && ip.IsLoopback() {
			// we found ::1, we can start the test
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cmd/ssh3/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = BuildWithEnvironment("../cmd/ssh3-server/main.go", []string{fmt.Sprintf("CGO_ENABLED=%s", os.Getenv("CGO_ENABLED"))})
		Expect(err).ToNot(HaveOccurred())
		serverCommand = exec.Command(ssh3ServerPath,
			"-bind", serverBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		serverCommand.Env = append(serverCommand.Env, "SSH3_LOG_LEVEL=debug")
		session, err := Start(serverCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBind] = session

		for tag, bind := range oldServerBinds {
			gobin, err := os.MkdirTemp("", fmt.Sprintf("ssh3-backwards-compatible-versions-%s", tag))
			Expect(err).ToNot(HaveOccurred())
			cmd := exec.Command("go", "install", fmt.Sprintf("github.com/francoismichel/ssh3/cmd/ssh3-server@%s", tag))
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, fmt.Sprintf("GOBIN=%s", gobin))
			err = cmd.Run()
			Expect(err).ToNot(HaveOccurred())
			serverPath := path.Join(gobin, "ssh3-server")
			Expect(err).ToNot(HaveOccurred())
			backwardsCompatibleServerCommand := exec.Command(serverPath,
				"-bind", bind,
				"-v",
				"-enable-password-login",
				"-url-path", DEFAULT_URL_PATH,
				"-cert", os.Getenv("CERT_PEM"),
				"-key", os.Getenv("CERT_PRIV_KEY"))
			serverCommand.Env = append(backwardsCompatibleServerCommand.Env, "SSH3_LOG_LEVEL=debug")
			session, err = Start(backwardsCompatibleServerCommand, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			serverSessions[bind] = session
		}

		proxyServerCommand = exec.Command(ssh3ServerPath,
			"-bind", proxyServerBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_PROXY_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		proxyServerCommand.Env = append(proxyServerCommand.Env, "SSH3_LOG_LEVEL=debug")
		proxyServerSession, err = Start(proxyServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[proxyServerBind] = proxyServerSession

		rsaPrivKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		ed25519PrivKeyPath = os.Getenv("TESTUSER_ED25519_PRIVKEY")
		ecdsaPrivKeyPath = os.Getenv("TESTUSER_ECDSA_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		ecdsaUsername = os.Getenv("ECDSATESTUSER_USERNAME")
		Expect(fileExists(rsaPrivKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
		err = os.WriteFile(fmt.Sprintf("/home/%s/.profile", username), []byte("echo 'hello from .profile'"), 0777)
		Expect(err).ToNot(HaveOccurred())
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	for _, serverSession := range serverSessions {
		serverSession.Terminate()
	}
})

var _ = Describe("Testing the ssh3 cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})
	})

	Context("With running server", func() {
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
			Consistently(serverSessions[serverBind], "200ms").ShouldNot(Exit())
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgsWithBind := func(privKeyPath string, bind string, additionalArgs ...string) []string {
				args := []string{
					"-v",
					"-insecure",
					"-privkey", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, bind, DEFAULT_URL_PATH))
				return args
			}
			getClientArgs := func(privKeyPath string, additionalArgs ...string) []string {
				return getClientArgsWithBind(privKeyPath, serverBind, additionalArgs...)
			}

			Context("Client behaviour", func() {
				It("Should connect using an RSA privkey", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an RSA privkey through proxy jump", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH)), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				for key, val := range oldServerBinds {
					// actually capture the values of key,val, as directly referring them in the code below will only keep the value of the last iteration
					tag, bind := key, val
					When("server version is"+tag+", bind is"+bind, func() {
						It("Should connect using an RSA privkey to old supported server", func() {
							clientArgs = append(getClientArgsWithBind(rsaPrivKeyPath, bind), "echo", "Hello, World!")
							command := exec.Command(ssh3Path, clientArgs...)
							session, err := Start(command, GinkgoWriter, GinkgoWriter)
							Expect(err).ToNot(HaveOccurred())
							Eventually(session).Should(Exit(0))
							Eventually(session).Should(Say("Hello, World!\n"))
						})
					})
				}

				It("Should connect using an ed25519 privkey", func() {
					clientArgs = append(getClientArgs(ed25519PrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ecdsa privkey", func() {
					// for retrocopatibility integration tests with version 0.1.5, we must perform ecdsa tests
					// for another user as ecdsa is not available on the server on older versions
					savedUsername := username
					username = ecdsaUsername
					clientArgs = append(getClientArgs(ecdsaPrivKeyPath), "echo", "Hello, World!")
					username = savedUsername
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(rsaPrivKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(rsaPrivKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(rsaPrivKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(rsaPrivKeyPath), "exit", "-1")

					command0 := exec.Command(ssh3Path, clientArgs0...)
					session, err := Start(command0, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))

					command1 := exec.Command(ssh3Path, clientArgs1...)
					session, err = Start(command1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(1))

					command255 := exec.Command(ssh3Path, clientArgs255...)
					session, err = Start(command255, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))

					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session, err = Start(commandMinus1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
				})

				It("Should run the interactive shell in login mode and read .profile", func() {
					clientArgs = getClientArgs(rsaPrivKeyPath)
					command := exec.Command(ssh3Path, clientArgs...)
					stdin, err := command.StdinPipe()
					Expect(err).ToNot(HaveOccurred())
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Consistently(session).ShouldNot(Exit())
					Eventually(session.Out).Should(Say("hello from .profile"))
					_, err = stdin.Write([]byte("exit\n")) // 0x04 = EOT character, closing the bash session
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
				})

				// It checks the client with the -forward-tcp or -reverse-tcp forwarding options.
				// As forward-tcp, a TCP socket is indeed well open on the client and is forwarded
				// through the SSH3 connection towards the specified remote IP and port at server´s reach.
				// When reverse-tcp is specified, a TCP socket is open on the server and forwarded through
				// the SSH3 connection towards the specified remote IP and port at client's reach.
				// As the server and the client are run on the same machine the same test can be reused
				// for both cases.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string, forwardingType string) {
						localIPBare := "::1"
						if remoteAddr.IP.To4() != nil {
							localIPBare = "127.0.0.1"
						}
						// The CLI spec is always <localPort>/<localIP>@<remotePort>/<remoteIP>
						// where the *local* pair lives on the ssh3 client side and the
						// *remote* pair lives on the ssh3 server side - same syntax for
						// -forward-tcp and -reverse-tcp.
						forwardSpec := fmt.Sprintf("%d/%s@%d/%s", localPort, localIPBare, remoteAddr.Port, remoteAddr.IP)

						// Decide which end runs the "origin" TCP server (the one that
						// answers) and which end the test will connect to.
						//
						//   -forward-tcp: client listens on (localIP,localPort); the
						//     server dials remoteAddr, so the origin lives on the
						//     server-side at remoteAddr and the test connects on the
						//     client-side at (localIP,localPort).
						//
						//   -reverse-tcp: server listens on remoteAddr; the client
						//     dials (localIP,localPort), so the origin lives on the
						//     client-side at (localIP,localPort) and the test connects
						//     on the server-side at remoteAddr.
						var originAddr *net.TCPAddr
						var entryAddr string
						switch forwardingType {
						case "-forward-tcp":
							originAddr = remoteAddr
							entryAddr = net.JoinHostPort(localIPBare, strconv.Itoa(int(localPort)))
						case "-reverse-tcp":
							originAddr = &net.TCPAddr{IP: net.ParseIP(localIPBare), Port: int(localPort)}
							entryAddr = net.JoinHostPort(remoteAddr.IP.String(), strconv.Itoa(remoteAddr.Port))
						default:
							Fail(fmt.Sprintf("unsupported forwardingType %q", forwardingType))
						}

						serverStarted := make(chan struct{})
						// Start the origin TCP server on whichever side is the "far end"
						// of the tunnel for this forwarding direction.
						go func() {
							defer close(serverStarted)
							defer GinkgoRecover()
							listener, err := net.ListenTCP("tcp", originAddr)
							Expect(err).ToNot(HaveOccurred())
							defer listener.Close()

							serverStarted <- struct{}{}

							conn, err := listener.Accept()
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()

							// Read message from client
							buffer := make([]byte, len(messageFromClient))
							_, err = conn.Read(buffer)
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))

							// Send message to client
							_, err = conn.Write([]byte(messageFromServer))
							Expect(err).ToNot(HaveOccurred())
							conn.(*net.TCPConn).CloseWrite()

							// Read from the client after receiving the message, assert EOF
							n, err := conn.Read(buffer)
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()

						Eventually(serverStarted).Should(Receive())
						// Execute the client with TCP port forwarding

						additionalArgs := []string{}
						if proxyJump {
							additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
						}
						additionalArgs = append(additionalArgs, forwardingType, forwardSpec)
						clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Try to connect to the entry-side of the tunnel.  For -forward
						// this is the client's local listener; for -reverse it is the
						// server's listener.
						var conn net.Conn
						// connection refused might happen between the time when the
						// process starts and actually listens on the socket
						Eventually(func() error {
							var err error
							conn, err = net.Dial("tcp", entryAddr)
							return err
						}).ShouldNot(HaveOccurred())
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						// Send message from client
						n, err := conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromClient)))

						// Close the client-side connection
						conn.(*net.TCPConn).CloseWrite()

						// Read message from server
						buffer := make([]byte, len(messageFromServer))
						conn.SetReadDeadline(time.Now().Add(1 * time.Second))
						n, err = conn.Read(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(string(buffer[:n])).To(Equal(messageFromServer))

						// If the messages are correctly exchanged, the forwarding is working as expected
						// Now, check that the TCP conn is well closed and that no additional byte was sent
						n, err = conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8090, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					It("works through proxy jump", func() {
						testTCPPortForwarding(8080, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8091, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8081, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-forward-tcp")
						testTCPPortForwarding(8092, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-reverse-tcp")
					})

					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						addrs, err := net.InterfaceAddrs()
						Expect(err).ToNot(HaveOccurred())
						if !IPv6LoopbackAvailable(addrs) {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8082, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-forward-tcp")
						testTCPPortForwarding(8093, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-reverse-tcp")
					})

					// Regression test for the repeatable -reverse-tcp / -forward-tcp
					// flags.  The autossh use case bundles several forwards into a
					// single ssh3 invocation; we verify that two reverse-tcp specs
					// given on the same command line both end up active and serve
					// independent origins on the client side.
					It("accepts multiple -reverse-tcp specifications at once", func() {
						// Two distinct client-side origins; the ssh3 server will be
						// asked to bind two distinct ports and relay each back to
						// its matching origin.
						originA, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer originA.Close()
						originB, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer originB.Close()
						originAPort := originA.Addr().(*net.TCPAddr).Port
						originBPort := originB.Addr().(*net.TCPAddr).Port

						// Pick two free server-side ports for the reverse
						// listeners.  There is an unavoidable TOCTOU window
						// here: between Close()-ing the probe and the ssh3
						// server reaching ListenTCP another process on the
						// host might grab the port.  In practice the window
						// is microseconds and the ports are in the kernel's
						// ephemeral range, so collisions are extremely
						// unlikely; the test will surface them clearly as a
						// "bind: address already in use" reverse-forward
						// setup failure.
						probeA, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						serverPortA := probeA.Addr().(*net.TCPAddr).Port
						probeA.Close()
						probeB, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						serverPortB := probeB.Addr().(*net.TCPAddr).Port
						probeB.Close()

						// Each origin responds with a deterministic tag so we can
						// tell them apart across the two tunnels.
						serveTag := func(l *net.TCPListener, tag string, done chan<- struct{}) {
							defer GinkgoRecover()
							defer close(done)
							c, err := l.Accept()
							if err != nil {
								return
							}
							defer c.Close()
							_, _ = c.Write([]byte(tag))
						}
						doneA := make(chan struct{})
						doneB := make(chan struct{})
						go serveTag(originA, "TAG_A", doneA)
						go serveTag(originB, "TAG_B", doneB)

						clientArgs := append(getClientArgs(rsaPrivKeyPath,
							"-reverse-tcp", fmt.Sprintf("%d/127.0.0.1@%d/127.0.0.1", originAPort, serverPortA),
							"-reverse-tcp", fmt.Sprintf("%d/127.0.0.1@%d/127.0.0.1", originBPort, serverPortB),
						), "sleep", "10")
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Both reverse listeners must come up on the server side.
						var connA, connB net.Conn
						Eventually(func() error {
							connA, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPortA))
							return err
						}, "5s").ShouldNot(HaveOccurred())
						defer connA.Close()
						Eventually(func() error {
							connB, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPortB))
							return err
						}, "5s").ShouldNot(HaveOccurred())
						defer connB.Close()

						// Read the tag from each tunnel.  Use a real
						// assertion on the read error - the previous
						// version dropped it on the floor, which would
						// mask a closed-channel race as an empty string
						// compared against "TAG_A".
						readTag := func(c net.Conn) (string, error) {
							buf := make([]byte, 16)
							c.SetReadDeadline(time.Now().Add(3 * time.Second))
							n, err := c.Read(buf)
							return string(buf[:n]), err
						}
						tagA, err := readTag(connA)
						Expect(err).ToNot(HaveOccurred())
						Expect(tagA).To(Equal("TAG_A"))
						tagB, err := readTag(connB)
						Expect(err).ToNot(HaveOccurred())
						Expect(tagB).To(Equal("TAG_B"))
						Eventually(doneA, "3s").Should(BeClosed())
						Eventually(doneB, "3s").Should(BeClosed())
					})

					// Regression test for -forward-tcp accepting a non-loopback
					// local bind address.  We ask ssh3 to bind its local listener
					// on 0.0.0.0, then verify it is reachable through 127.0.0.1
					// (which is one of the addresses 0.0.0.0 covers).
					It("binds local-forward listener on 0.0.0.0 when requested", func() {
						origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer origin.Close()
						originPort := origin.Addr().(*net.TCPAddr).Port

						probe, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						clientPort := probe.Addr().(*net.TCPAddr).Port
						probe.Close()

						done := make(chan struct{})
						go func() {
							defer GinkgoRecover()
							defer close(done)
							c, err := origin.Accept()
							if err != nil {
								return
							}
							defer c.Close()
							c.Write([]byte("VIA_ZERO"))
						}()

						clientArgs := append(getClientArgs(rsaPrivKeyPath,
							"-forward-tcp", fmt.Sprintf("%d/0.0.0.0@%d/127.0.0.1", clientPort, originPort),
						), "sleep", "5")
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Confirm the bind happened on 0.0.0.0 by reaching it via
						// the loopback alias.
						var conn net.Conn
						Eventually(func() error {
							conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
							return err
						}).ShouldNot(HaveOccurred())
						defer conn.Close()

						buf := make([]byte, 16)
						conn.SetReadDeadline(time.Now().Add(2 * time.Second))
						n, _ := conn.Read(buf)
						Expect(string(buf[:n])).To(Equal("VIA_ZERO"))
						<-done
					})

					// ExitOnForwardFailure-equivalent behaviour: if the server
					// cannot open the reverse-tcp listener (here, because the
					// port is already in use), the client must surface that
					// error and exit non-zero rather than silently proceed.
					It("exits non-zero when the server cannot bind the reverse-tcp listener", func() {
						// Hold a port on the server side so ListenTCP fails there.
						blocker, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer blocker.Close()
						blockedPort := blocker.Addr().(*net.TCPAddr).Port

						clientArgs := append(getClientArgs(rsaPrivKeyPath,
							"-reverse-tcp", fmt.Sprintf("9999/127.0.0.1@%d/127.0.0.1", blockedPort),
						), "sleep", "5")
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						Eventually(session, "10s").Should(Exit())
						Expect(session.ExitCode()).ToNot(Equal(0),
							"client should fail when the server cannot bind the reverse-tcp port")
						// The reason string the server attaches to the
						// ack-Fail message must surface in the client's
						// stderr - otherwise we are passing the test for
						// the wrong reason (e.g. a generic disconnect).
						Expect(session.Err).To(Say("address already in use"))
					})

					// Same as above but with -proxy-jump in the mix, to make sure
					// the ack handshake survives the proxy hop.  Beyond the
					// non-zero exit code we also assert that stderr carries
					// the *target* server's bind error verbatim - that is
					// only possible if the request and the ack actually
					// crossed the proxy, since the target server's listener
					// is the only thing that can fail with "address already
					// in use" for the chosen port.
					It("exits non-zero on reverse-tcp bind failure through proxy jump", func() {
						blocker, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer blocker.Close()
						blockedPort := blocker.Addr().(*net.TCPAddr).Port

						clientArgs := append(getClientArgs(rsaPrivKeyPath,
							"-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH),
							"-reverse-tcp", fmt.Sprintf("9999/127.0.0.1@%d/127.0.0.1", blockedPort),
						), "sleep", "5")
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						Eventually(session, "15s").Should(Exit())
						Expect(session.ExitCode()).ToNot(Equal(0),
							"client should fail through proxy jump when the server cannot bind the reverse-tcp port")
						// The reason string is forwarded from the target
						// server through the proxy to the client - seeing
						// the target's specific bind error here is the
						// evidence that the ack survived the hop.
						Expect(session.Err).To(Say("address already in use"))
					})
				})
			})

			// It checks the client with the -forward-udp or -reverse-udp forwarding options.
 			// As forward-tcp, a TCP socket is indeed well open on the client and is forwarded
 			// through the SSH3 connection towards the specified remote IP and port at server´s reach.
 			// When reverse-tcp is specified, a UDP socket is open on the server and forwarded through
 			// the SSH3 connection towards the specified remote IP and port at client's reach.
 			// As the server and the client are run on the same machine the same test can be reused
 			// for both cases.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string, forwardingType string) {
					localIPBare := "::1"
					if remoteAddr.IP.To4() != nil {
						localIPBare = "127.0.0.1"
					}
					forwardSpec := fmt.Sprintf("%d/%s@%d/%s", localPort, localIPBare, remoteAddr.Port, remoteAddr.IP)

					// See testTCPPortForwarding for the role flip between forward and
					// reverse: the "origin" UDP server lives on the far side of the
					// tunnel, the test entry point on the near side.
					var originAddr *net.UDPAddr
					var entryAddr string
					switch forwardingType {
					case "-forward-udp":
						originAddr = remoteAddr
						entryAddr = net.JoinHostPort(localIPBare, strconv.Itoa(int(localPort)))
					case "-reverse-udp":
						originAddr = &net.UDPAddr{IP: net.ParseIP(localIPBare), Port: int(localPort)}
						entryAddr = net.JoinHostPort(remoteAddr.IP.String(), strconv.Itoa(remoteAddr.Port))
					default:
						Fail(fmt.Sprintf("unsupported forwardingType %q", forwardingType))
					}

					serverStarted := make(chan struct{})
					// Start the origin UDP server on the far side of the tunnel.
					go func() {
						defer close(serverStarted)
						defer GinkgoRecover()
						conn, err := net.ListenUDP("udp", originAddr)
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						serverStarted <- struct{}{}

						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := conn.ReadFromUDP(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(string(buffer[:n])).To(Equal(messageFromClient))

						// Send message to client
						_, err = conn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()

					Eventually(serverStarted).Should(Receive())
					// Execute the client with UDP port forwarding

					additionalArgs := []string{}
					if proxyJump {
						additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
					}
					additionalArgs = append(additionalArgs, forwardingType, forwardSpec)
					clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer session.Terminate()

					// Wait until the tunnel entry point is actually reachable
					// instead of sleeping for a hard-coded duration: the
					// previous time.Sleep(2*time.Second) was both racy on a
					// loaded CI box and wasteful on a fast one.
					var conn net.Conn
					Eventually(func() error {
						var err error
						conn, err = net.Dial("udp", entryAddr)
						return err
					}, "5s").ShouldNot(HaveOccurred())
					defer conn.Close()

					// Send message from client.  We retry the send/read pair
					// in Eventually because UDP packets sent before the
					// server-side bind side of a -reverse-udp forward is
					// fully wired up will be dropped silently; the deadline
					// covers both the initial setup race and the round-trip.
					buffer := make([]byte, 2*len(messageFromServer))
					var n int
					Eventually(func() error {
						if _, werr := conn.Write([]byte(messageFromClient)); werr != nil {
							return werr
						}
						conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
						var rerr error
						n, rerr = conn.Read(buffer)
						return rerr
					}, "5s").ShouldNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))
				}

				It("works with small messages", func() {
					testUDPPortForwarding(8080, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8090, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

				It("works through proxy jump", func() {
					testUDPPortForwarding(8080, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8091, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-forward-udp")
					testUDPPortForwarding(8092, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer), "-reverse-udp")
				})

				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					addrs, err := net.InterfaceAddrs()
					Expect(err).ToNot(HaveOccurred())
					if !IPv6LoopbackAvailable(addrs) {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8082, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-forward-udp")
					testUDPPortForwarding(8093, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9090}, "hello from client", "hello from server", "-reverse-udp")
				})

			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Eventually(string(session.Wait().Err.Contents())).Should(ContainSubstring("unauthorized"))
				})
			})

			// Exercises the QUIC connection-migration coordinator
			// end-to-end: build a throw-away netns with two veth
			// pairs into the host, run an ssh3 client inside it with
			// -enable-migration, flip the default route, and assert
			// that (a) a long-lived reverse-tcp forward stays
			// reachable across the route swap and (b) the server
			// logs the expected "peer migrated" line.
			//
			// This spec must Skip() - not fail - when prerequisites
			// are unmet (non-root, no `ip`, no netns support).  The
			// existing run_integration_tests.sh runs the suite under
			// sudo so the privilege check should normally pass.
			Context("Connection migration", func() {
				// runMigrationSpec implements the body of the
				// migration test in a way that can be parameterised
				// over whether -proxy-jump is in the picture or not.
				//
				// Topology (see netnsEnv): three namespaces
				// (client_ns, proxy_ns, target_ns) connected by
				// real veth pairs - no DNAT, no loopback overload.
				//
				// Both variants spawn DEDICATED ssh3-server
				// processes inside their target namespaces (rather
				// than reusing the BeforeSuite host-side servers)
				// so that every QUIC endpoint has a routable real
				// address.  This is what makes proxy-jump migration
				// actually testable: the proxy can dial the target
				// over its own veth, the client reaches the proxy
				// through the host's IP-forwarding, and the swapped
				// default route inside client_ns produces a real
				// source-IP change on the proxy leg.
				//
				// What we assert:
				//   - direct: target server logs "peer migrated
				//     for user X" after the route swap.
				//   - proxy-jump: *proxy* server logs it.  Target
				//     server does NOT migrate - its peer is the
				//     proxy's loopback UDP-forward endpoint, which
				//     does not change when the client↔proxy path
				//     does.
				runMigrationSpec := func(proxyJump bool) {
					if os.Geteuid() != 0 {
						Skip("netns migration test requires root")
					}
					if _, err := exec.LookPath("ip"); err != nil {
						Skip("iproute2 'ip' binary not found in PATH")
					}
					if _, err := exec.LookPath("iptables"); err != nil {
						Skip("iptables binary not found in PATH (needed to ACCEPT inter-namespace forwarding)")
					}

					env := newNetnsEnv()
					if err := env.setup(); err != nil {
						_ = env.teardown()
						msg := err.Error()
						if strings.Contains(msg, "operation not permitted") ||
							strings.Contains(msg, "permission denied") ||
							strings.Contains(msg, "read-only file system") ||
							strings.Contains(msg, "kernel may lack netns") {
							Skip("cannot build netns topology in this sandbox: " + msg)
						}
						Fail("netns setup failed: " + msg)
					}
					defer func() {
						if err := env.teardown(); err != nil {
							fmt.Fprintf(GinkgoWriter, "netns teardown error: %v\n", err)
						}
					}()

					// Pick free ports for the dedicated servers in
					// each variant.  Picking ephemeral ports up front
					// (probe-and-close TOCTOU) is acceptable here
					// because the namespaces are throw-away.
					reservePort := func() int {
						l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
						Expect(err).ToNot(HaveOccurred())
						defer l.Close()
						return l.Addr().(*net.TCPAddr).Port
					}
					targetPort := reservePort()
					proxyPort := reservePort()
					reversePort := reservePort()

					// Spawn the target ssh3-server in target_ns
					// (proxy-jump) or in the *host* network namespace
					// bound to the client-reachable address (direct).
					//
					// For direct mode we bind on 0.0.0.0 of the
					// HOST so that both pair-A (10.99.0.1) and pair-B
					// (10.99.0.5) addresses accept the client's
					// connection, which is what makes the
					// post-swap path keep working.
					targetServerCmd := func() *exec.Cmd {
						if proxyJump {
							return exec.Command("ip", "netns", "exec", env.targetNS,
								ssh3ServerPath,
								"-bind", fmt.Sprintf("0.0.0.0:%d", targetPort),
								"-v",
								"-url-path", DEFAULT_URL_PATH,
								"-cert", os.Getenv("CERT_PEM"),
								"-key", os.Getenv("CERT_PRIV_KEY"))
						}
						return exec.Command(ssh3ServerPath,
							"-bind", fmt.Sprintf("0.0.0.0:%d", targetPort),
							"-v",
							"-url-path", DEFAULT_URL_PATH,
							"-cert", os.Getenv("CERT_PEM"),
							"-key", os.Getenv("CERT_PRIV_KEY"))
					}()
					targetServerCmd.Env = append(targetServerCmd.Env, "SSH3_LOG_LEVEL=debug")
					targetServerSession, err := Start(targetServerCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer targetServerSession.Terminate()

					// Proxy server runs in proxy_ns only when proxy-
					// jump is exercised.
					var proxyServerSession *Session
					if proxyJump {
						proxyServerCmd := exec.Command("ip", "netns", "exec", env.proxyNS,
							ssh3ServerPath,
							"-bind", fmt.Sprintf("0.0.0.0:%d", proxyPort),
							"-v",
							"-url-path", DEFAULT_PROXY_URL_PATH,
							"-cert", os.Getenv("CERT_PEM"),
							"-key", os.Getenv("CERT_PRIV_KEY"))
						proxyServerCmd.Env = append(proxyServerCmd.Env, "SSH3_LOG_LEVEL=debug")
						proxyServerSession, err = Start(proxyServerCmd, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer proxyServerSession.Terminate()
					}

					// Wait for the target server to bind.  The session
					// stderr says "Server started, listening on …".
					Eventually(targetServerSession.Err, "5s").Should(Say("Server started, listening on"))
					if proxyServerSession != nil {
						Eventually(proxyServerSession.Err, "5s").Should(Say("Server started, listening on"))
					}

					// Origin TCP server lives on the client side
					// (inside client_ns).  When something on the
					// server side dials the reverse-tcp listener,
					// the ssh3 client dials this origin locally via
					// the tunnel.  Must be up before the ssh3 client
					// answers the first probe.
					originPort := reservePort()
					var originCmd *exec.Cmd
					if _, err := exec.LookPath("socat"); err == nil {
						originCmd = exec.Command("ip", "netns", "exec", env.clientNS,
							"socat", fmt.Sprintf("TCP-LISTEN:%d,bind=127.0.0.1,reuseaddr,fork", originPort),
							"SYSTEM:'printf TUNNEL_OK'")
					} else if _, err := exec.LookPath("python3"); err == nil {
						py := fmt.Sprintf(`
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", %d))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        c.sendall(b"TUNNEL_OK")
    finally:
        c.close()
`, originPort)
						originCmd = exec.Command("ip", "netns", "exec", env.clientNS, "python3", "-c", py)
					} else {
						Skip("need socat or python3 to run the origin TCP server inside the netns")
					}
					originCmd.Stdout = GinkgoWriter
					originCmd.Stderr = GinkgoWriter
					Expect(originCmd.Start()).To(Succeed())
					defer func() {
						_ = originCmd.Process.Kill()
						_, _ = originCmd.Process.Wait()
					}()
					Eventually(func() error {
						out, err := exec.Command("ip", "netns", "exec", env.clientNS,
							"sh", "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d", originPort)).CombinedOutput()
						if err != nil {
							return fmt.Errorf("origin not yet listening: %v: %s", err, string(out))
						}
						return nil
					}, "5s", "100ms").ShouldNot(HaveOccurred())

					// Settle any netlink events generated by env.setup
					// (interface up, route add, address assignment)
					// before the ssh3 client - and its migration
					// watcher - starts.  Without this the watcher
					// catches the tail end of the setup burst and
					// fires a migration mid-tunnel-setup.  P1.2(b)
					// will replace this with a timestamp-filter in
					// the coordinator itself.
					time.Sleep(1500 * time.Millisecond)

					// Target URL: in direct mode the host's pair-A
					// address (the initial default route target);
					// in proxy-jump mode the target_ns address, which
					// the proxy can reach over its own veth.
					targetHostPort := fmt.Sprintf("%s:%d", env.vethCAOuterIP, targetPort)
					if proxyJump {
						targetHostPort = fmt.Sprintf("%s:%d", env.vethTInnerIP, targetPort)
					}

					clientArgs := []string{
						"netns", "exec", env.clientNS,
						ssh3Path,
						"-v",
						"-insecure",
						"-privkey", rsaPrivKeyPath,
						"-enable-migration",
					}
					if proxyJump {
						clientArgs = append(clientArgs,
							"-proxy-jump", fmt.Sprintf("%s@%s:%d%s", username, env.vethPInnerIP, proxyPort, DEFAULT_PROXY_URL_PATH),
						)
					}
					clientArgs = append(clientArgs,
						"-reverse-tcp", fmt.Sprintf("%d/127.0.0.1@%d/0.0.0.0", originPort, reversePort),
						fmt.Sprintf("%s@%s%s", username, targetHostPort, DEFAULT_URL_PATH),
						"sleep", "60",
					)
					clientCmd := exec.Command("ip", clientArgs...)
					clientSession, err := Start(clientCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer clientSession.Terminate()

					// reverseDialAddr is where the test connects from
					// to verify the tunnel: the target server's bind
					// (so 0.0.0.0:reversePort) is reachable via the
					// target_ns IP in proxy-jump mode, or the host's
					// pair-A address in direct mode.
					var reverseDialAddr string
					if proxyJump {
						reverseDialAddr = fmt.Sprintf("%s:%d", env.vethTInnerIP, reversePort)
					} else {
						reverseDialAddr = fmt.Sprintf("%s:%d", env.vethCAOuterIP, reversePort)
					}

					setupBudget := "10s"
					if proxyJump {
						setupBudget = "30s"
					}
					var preConn net.Conn
					Eventually(func() error {
						var derr error
						preConn, derr = net.Dial("tcp", reverseDialAddr)
						return derr
					}, setupBudget).ShouldNot(HaveOccurred())
					buf := make([]byte, 16)
					preConn.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, _ := preConn.Read(buf)
					Expect(string(buf[:n])).To(Equal("TUNNEL_OK"))
					preConn.Close()

					// Trigger the migration.
					Expect(env.swapDefaultRoute()).To(Succeed())

					postBudget := "15s"
					if proxyJump {
						postBudget = "25s"
					}
					Eventually(func() error {
						c, derr := net.Dial("tcp", reverseDialAddr)
						if derr != nil {
							return derr
						}
						defer c.Close()
						c.SetReadDeadline(time.Now().Add(2 * time.Second))
						b := make([]byte, 16)
						k, rerr := c.Read(b)
						if rerr != nil {
							return rerr
						}
						if string(b[:k]) != "TUNNEL_OK" {
							return fmt.Errorf("unexpected tag %q", string(b[:k]))
						}
						return nil
					}, postBudget, "250ms").ShouldNot(HaveOccurred())

					// Migration log line lands on the *proxy* server
					// in proxy-jump mode (the only QUIC connection
					// whose source IP changed); on the target server
					// otherwise.
					migrationServer := targetServerSession.Err
					if proxyJump {
						migrationServer = proxyServerSession.Err
					}
					Eventually(migrationServer, "15s").Should(
						Say(fmt.Sprintf("peer migrated for user %s", username)))
				}

				It("survives a default-route swap inside a netns", func() {
					runMigrationSpec(false)
				})

				// PIt: pending.  3-namespace topology now rules out
				// the "DNAT/loopback" hypothesis from the previous
				// debug round - the primary client→proxy QUIC leg
				// completes cleanly (proxy server logs CONNECT 200
				// OK against the real 10.99.1.2 address, no DNAT in
				// play), so host forwarding and rp_filter are NOT
				// the problem.  What still fails is the *target*
				// leg: after proxyClient.ForwardUDP opens a local
				// listener inside client_ns ("started proxy jump at
				// 127.0.0.1:43807"), the target QUIC dial to that
				// loopback endpoint still times out before the
				// handshake completes.  This means the bug is in
				// how the target-conversation datagrams ride the
				// proxy's UDP-forwarding channel (cmd/ssh3-server.go's
				// handleUDPForwardingChannel + the client-side
				// ForwardUDP go-routine), not in the netns harness.
				//
				// Hypotheses to investigate next (require qlog +
				// tcpdump on each veth):
				//   - handshake-initial QUIC packets get clamped
				//     somewhere between client→ForwardUDP local
				//     listener → primary QUIC datagrams → proxy →
				//     proxy.DialUDP(target) → target;
				//   - return path target → proxy → primary QUIC
				//     datagrams → client.ForwardUDP local listener
				//     → target-leg QUIC dial socket does not pin
				//     to the same source-port pair after the proxy's
				//     ephemeral source-port reassignment;
				//   - quic-go's datagram path has a queue-depth
				//     limit that drops handshake packets at this
				//     particular timing.
				//
				// Until the right hypothesis is confirmed, the
				// spec stays PIt; the README's caveat still stands.
				PIt("survives a default-route swap inside a netns with proxy-jump", func() {
					runMigrationSpec(true)
				})
			})
		})
	})
})
