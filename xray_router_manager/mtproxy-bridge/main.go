// The MTProxy ingress bridge: SOCKS5 on the Compose network → VLESS on the router's Unix socket.
//
// Telemt runs on the Compose bridge network and the Xray-router on the host network, so Telemt
// cannot reach the router's loopback ingresses, and a connection from the bridge to an address of
// the host meets the host's firewall. A Unix socket in a volume both containers share crosses the
// namespaces without one. Xray listens on a socket only with `vless` (its `socks` inbound ignores a
// socket path, and its outbounds cannot dial one), and Telemt dials only TCP SOCKS5: this process
// is the one piece between them.
//
//	Telemt ── SOCKS5 CONNECT, username/password ──▶ bridge :45103
//	bridge ── VLESS request (version 0, uuid, no addons, TCP, port, address) ──▶ router socket
//	then bytes both ways; the VLESS response header (version, addons) is cut off the first reply
//
// The credential ({uuid, username, password}) is the router manager's: it writes a copy next to
// the socket and the bridge rereads it when the file changes. No routing happens here — the router
// decides where the connection leaves by the `mtproxy` inbound's rules.
//
// 3.0: Go instead of Python. Every MTProxy byte routed through the router crosses this process;
// the kernel now moves them (splice) and a health check costs a millisecond, not a Python start.
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	listenHost       = "0.0.0.0"
	listenPort       = "45103"
	maxConnections   = 4096
	handshakeTimeout = 10 * time.Second
)

// SOCKS5 replies (RFC 1928 §6).
const (
	replyOK         = 0
	replyFailure    = 1
	replyNotAllowed = 2
	replyCommand    = 7
	replyAddress    = 8
)

var logger = log.New(os.Stderr, "xray_router_bridge: ", 0)

type refused struct{ reply byte }

func (r refused) Error() string { return fmt.Sprintf("refused (%d)", r.reply) }

// secret is the router's credential: the VLESS uuid and the SOCKS5 login Telemt presents.
type secret struct {
	uuid     [16]byte
	username []byte
	password []byte
}

// credential is the router's credential file, reread whenever its mtime or size changes.
type credential struct {
	path  string
	mu    sync.Mutex
	stamp [2]int64
	value *secret
}

func (c *credential) load() (*secret, error) {
	info, err := os.Stat(c.path)
	if err != nil {
		return nil, err
	}
	stamp := [2]int64{info.ModTime().UnixNano(), info.Size()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != nil && stamp == c.stamp {
		return c.value, nil
	}
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}
	var record struct {
		UUID     *string `json:"uuid"`
		Username *string `json:"username"`
		Password *string `json:"password"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	if record.UUID == nil || record.Username == nil || record.Password == nil {
		return nil, errors.New("incomplete credential")
	}
	id, err := parseUUID(*record.UUID)
	if err != nil {
		return nil, err
	}
	c.stamp, c.value = stamp, &secret{uuid: id, username: []byte(*record.Username), password: []byte(*record.Password)}
	return c.value, nil
}

func parseUUID(text string) ([16]byte, error) {
	var id [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(text), "-", "")
	if len(clean) != 32 {
		return id, errors.New("malformed uuid")
	}
	if _, err := hex.Decode(id[:], []byte(clean)); err != nil {
		return id, errors.New("malformed uuid")
	}
	return id, nil
}

// vlessRequest is the VLESS request header for a TCP CONNECT. `address` is what SOCKS5 carried:
// 4 bytes for IPv4, 16 for IPv6, the name for a domain (VLESS: 1 IPv4, 2 domain, 3 IPv6).
func vlessRequest(uuid [16]byte, atyp byte, address []byte, port uint16) ([]byte, error) {
	header := make([]byte, 0, 1+16+1+1+2+2+len(address))
	header = append(header, 0)
	header = append(header, uuid[:]...)
	header = append(header, 0, 1)
	header = binary.BigEndian.AppendUint16(header, port)
	switch atyp {
	case 1:
		header = append(header, 1)
	case 3:
		header = append(header, 2, byte(len(address)))
	case 4:
		header = append(header, 3)
	default:
		return nil, refused{replyAddress}
	}
	return append(header, address...), nil
}

func readByte(r io.Reader) (byte, error) {
	var one [1]byte
	_, err := io.ReadFull(r, one[:])
	return one[0], err
}

func readN(r io.Reader, n int) ([]byte, error) {
	buffer := make([]byte, n)
	_, err := io.ReadFull(r, buffer)
	return buffer, err
}

// handshake is the greeting, username/password (RFC 1929) and the CONNECT request: (atyp, address, port).
func handshake(conn net.Conn, want *secret) (byte, []byte, uint16, error) {
	head, err := readN(conn, 2)
	if err != nil {
		return 0, nil, 0, err
	}
	methods, err := readN(conn, int(head[1]))
	if err != nil {
		return 0, nil, 0, err
	}
	if head[0] != 5 || !bytes.Contains(methods, []byte{2}) {
		conn.Write([]byte{5, 0xff})
		return 0, nil, 0, refused{replyNotAllowed}
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return 0, nil, 0, err
	}
	auth, err := readN(conn, 2)
	if err != nil {
		return 0, nil, 0, err
	}
	username, err := readN(conn, int(auth[1]))
	if err != nil {
		return 0, nil, 0, err
	}
	length, err := readByte(conn)
	if err != nil {
		return 0, nil, 0, err
	}
	password, err := readN(conn, int(length))
	if err != nil {
		return 0, nil, 0, err
	}
	userOK := subtle.ConstantTimeCompare(username, want.username)
	passwordOK := subtle.ConstantTimeCompare(password, want.password)
	allowed := auth[0] == 1 && userOK&passwordOK == 1
	status := byte(1)
	if allowed {
		status = 0
	}
	if _, err := conn.Write([]byte{1, status}); err != nil {
		return 0, nil, 0, err
	}
	if !allowed {
		return 0, nil, 0, refused{replyNotAllowed}
	}
	request, err := readN(conn, 4)
	if err != nil {
		return 0, nil, 0, err
	}
	var address []byte
	switch atyp := request[3]; atyp {
	case 1:
		address, err = readN(conn, 4)
	case 3:
		var n byte
		if n, err = readByte(conn); err == nil {
			address, err = readN(conn, int(n))
		}
	case 4:
		address, err = readN(conn, 16)
	default:
		return 0, nil, 0, refused{replyAddress}
	}
	if err != nil {
		return 0, nil, 0, err
	}
	port, err := readN(conn, 2)
	if err != nil {
		return 0, nil, 0, err
	}
	if request[0] != 5 || request[1] != 1 {
		return 0, nil, 0, refused{replyCommand}
	}
	return request[3], address, binary.BigEndian.Uint16(port), nil
}

func reply(code byte) []byte {
	return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
}

type halfCloser interface{ CloseWrite() error }

func closeWrite(conn net.Conn) {
	if c, ok := conn.(halfCloser); ok {
		c.CloseWrite()
	}
}

// pump copies until EOF and passes the EOF on (half-close), as the router and Telemt expect.
func pump(dst, src net.Conn) {
	io.Copy(dst, src)
	closeWrite(dst)
}

// pumpResponse is router → client with the VLESS response header (version, addons length, addons) cut off.
func pumpResponse(dst, src net.Conn) {
	head, err := readN(src, 2)
	if err == nil && head[1] > 0 {
		_, err = readN(src, int(head[1]))
	}
	if err != nil {
		closeWrite(dst)
		return
	}
	pump(dst, src)
}

type bridge struct {
	socketPath string
	credential *credential
	slots      chan struct{}
}

func newBridge(socketPath, credentialPath string, connections int) *bridge {
	return &bridge{socketPath: socketPath, credential: &credential{path: credentialPath}, slots: make(chan struct{}, connections)}
}

func (b *bridge) handle(conn net.Conn) {
	select {
	case b.slots <- struct{}{}:
	default:
		conn.Close()
		return
	}
	defer func() { <-b.slots }()
	defer conn.Close()
	want, err := b.credential.load()
	if err != nil {
		logger.Print("no ingress credential yet: is the router up?")
		return
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	atyp, address, port, err := handshake(conn, want)
	var request []byte
	if err == nil {
		request, err = vlessRequest(want.uuid, atyp, address, port)
	}
	var refusal refused
	if errors.As(err, &refusal) {
		if refusal.reply != replyNotAllowed {
			conn.Write(reply(refusal.reply))
		}
		return
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write(reply(replyFailure))
		return
	}
	if err != nil {
		return
	}
	upstream, err := net.DialTimeout("unix", b.socketPath, handshakeTimeout)
	if err != nil {
		conn.Write(reply(replyFailure))
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(request); err != nil {
		return
	}
	if _, err := conn.Write(reply(replyOK)); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		pump(upstream, conn)
	}()
	pumpResponse(conn, upstream)
	done.Wait()
}

func (b *bridge) serve(listener net.Listener) error {
	backoff := 5 * time.Millisecond
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of descriptors and the like: wait instead of spinning, as asyncio's server does.
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		go b.handle(conn)
	}
}

// check is the container's health: the listener accepts and answers a SOCKS5 greeting.
func check(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return false
	}
	answer, err := readN(conn, 2)
	return err == nil && answer[0] == 5 && answer[1] == 2
}

func listenAddress() (string, string, error) {
	value := strings.TrimSpace(os.Getenv("XRAY_ROUTER_BRIDGE_LISTEN"))
	if value == "" {
		value = listenHost + ":" + listenPort
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("XRAY_ROUTER_BRIDGE_LISTEN must be ip:port, got %q", value)
	}
	return host, port, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	host, port, err := listenAddress()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	arguments := os.Args[1:]
	if len(arguments) == 1 && arguments[0] == "--check" {
		probe := host
		if host == listenHost {
			probe = "127.0.0.1"
		}
		if check(net.JoinHostPort(probe, port), 2*time.Second) {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if len(arguments) > 0 {
		fmt.Fprintln(os.Stderr, "usage: mtproxy-bridge [--check]")
		os.Exit(1)
	}
	socketPath := env("XRAY_ROUTER_INGRESS_MTPROXY_SOCKET", "/run/xray-router/ingress-mtproxy.sock")
	credentialPath := env("XRAY_ROUTER_INGRESS_MTPROXY_CREDENTIAL", socketPath[:strings.LastIndex(socketPath, "/")+1]+"ingress-mtproxy.json")
	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		logger.Fatal(err)
	}
	logger.Fatal(newBridge(socketPath, credentialPath, maxConnections).serve(listener))
}
