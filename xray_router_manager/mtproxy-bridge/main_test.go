package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testUUID = "11111111-2222-4333-8444-555555555555"

func writeCredential(t *testing.T, path, password string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"uuid": testUUID, "username": "telemt", "password": password})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

type seenRequest struct {
	header  []byte
	address []byte
}

// fakeRouter is a VLESS server: records the request header, answers `\x00\x00` + the payload upper-cased.
func fakeRouter(t *testing.T, path string) chan seenRequest {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	seen := make(chan seenRequest, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				head, err := readN(conn, 22)
				if err != nil {
					return
				}
				var address []byte
				switch head[21] {
				case 1:
					address, _ = readN(conn, 4)
				case 2:
					n, _ := readByte(conn)
					address, _ = readN(conn, int(n))
				default:
					address, _ = readN(conn, 16)
				}
				seen <- seenRequest{head, address}
				buffer := make([]byte, 1024)
				n, _ := conn.Read(buffer)
				conn.Write(append([]byte{0, 0}, bytes.ToUpper(buffer[:n])...))
			}(conn)
		}
	}()
	return seen
}

func startBridge(t *testing.T, dir string, connections int) (string, *bridge) {
	t.Helper()
	b := newBridge(filepath.Join(dir, "ingress-mtproxy.sock"), filepath.Join(dir, "ingress-mtproxy.json"), connections)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go b.serve(listener)
	return listener.Addr().String(), b
}

type outcome struct {
	method, auth []byte
	reply        int
	data         []byte
}

func socks(t *testing.T, address string, atyp byte, target []byte, payload []byte, user, password string, methods []byte, command byte) outcome {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(append([]byte{5, byte(len(methods))}, methods...))
	choice, err := readN(conn, 2)
	if err != nil || !bytes.Equal(choice, []byte{5, 2}) {
		return outcome{method: choice, reply: -1}
	}
	login := append([]byte{1, byte(len(user))}, user...)
	login = append(append(login, byte(len(password))), password...)
	conn.Write(login)
	auth, err := readN(conn, 2)
	if err != nil || !bytes.Equal(auth, []byte{1, 0}) {
		return outcome{auth: auth, reply: -1}
	}
	request := []byte{5, command, 0, atyp}
	if atyp == 3 {
		request = append(request, byte(len(target)))
	}
	request = binary.BigEndian.AppendUint16(append(request, target...), 443)
	conn.Write(request)
	answer, err := readN(conn, 10)
	if err != nil {
		return outcome{reply: -2}
	}
	if answer[1] != 0 {
		return outcome{reply: int(answer[1])}
	}
	conn.Write(payload)
	data, _ := io.ReadAll(conn)
	return outcome{reply: 0, data: data}
}

func TestVlessRequestHeaderForEachAddressKind(t *testing.T) {
	id, _ := parseUUID(testUUID)
	ipv4, _ := vlessRequest(id, 1, []byte{149, 154, 167, 51}, 443)
	want := append(append([]byte{0}, id[:]...), 0, 1, 1, 0xbb, 1, 149, 154, 167, 51)
	if !bytes.Equal(ipv4, want) {
		t.Fatalf("ipv4 header %x", ipv4)
	}
	domain, _ := vlessRequest(id, 3, []byte("t.me"), 443)
	if !bytes.Equal(domain[21:], []byte("\x02\x04t.me")) {
		t.Fatalf("domain header %x", domain)
	}
	ipv6, _ := vlessRequest(id, 4, make([]byte, 16), 443)
	if ipv6[21] != 3 || len(ipv6) != 22+16 {
		t.Fatalf("ipv6 header %x", ipv6)
	}
	if _, err := vlessRequest(id, 9, nil, 443); err == nil {
		t.Fatal("an unknown address kind must be refused")
	}
}

func TestConnectBecomesVlessAndBytesFlowBothWays(t *testing.T) {
	cases := []struct {
		atyp, vless byte
		address     []byte
	}{
		{1, 1, []byte{149, 154, 167, 51}},
		{3, 2, []byte("telegram.org")},
		{4, 3, append([]byte{0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0x80, 0x01}, 0, 0, 0, 0, 0, 0, 0, 0x0a)},
	}
	for _, c := range cases {
		dir := t.TempDir()
		writeCredential(t, filepath.Join(dir, "ingress-mtproxy.json"), strings.Repeat("p", 32))
		seen := fakeRouter(t, filepath.Join(dir, "ingress-mtproxy.sock"))
		address, _ := startBridge(t, dir, maxConnections)
		got := socks(t, address, c.atyp, c.address, []byte("hello"), "telemt", strings.Repeat("p", 32), []byte{2}, 1)
		if got.reply != 0 || string(got.data) != "HELLO" {
			t.Fatalf("atyp %d: %+v", c.atyp, got)
		}
		request := <-seen
		id, _ := parseUUID(testUUID)
		if request.header[0] != 0 || !bytes.Equal(request.header[1:17], id[:]) || request.header[17] != 0 ||
			request.header[18] != 1 || binary.BigEndian.Uint16(request.header[19:21]) != 443 ||
			request.header[21] != c.vless || !bytes.Equal(request.address, c.address) {
			t.Fatalf("atyp %d: router saw %x %x", c.atyp, request.header, request.address)
		}
	}
}

func TestWrongPasswordNoLoginAndBindAreRefusedBeforeTheRouter(t *testing.T) {
	dir := t.TempDir()
	writeCredential(t, filepath.Join(dir, "ingress-mtproxy.json"), strings.Repeat("p", 32))
	seen := fakeRouter(t, filepath.Join(dir, "ingress-mtproxy.sock"))
	address, _ := startBridge(t, dir, maxConnections)
	wrong := socks(t, address, 1, make([]byte, 4), []byte("x"), "telemt", strings.Repeat("q", 32), []byte{2}, 1)
	anonymous := socks(t, address, 1, make([]byte, 4), []byte("x"), "telemt", strings.Repeat("p", 32), []byte{0}, 1)
	bind := socks(t, address, 1, make([]byte, 4), []byte("x"), "telemt", strings.Repeat("p", 32), []byte{2}, 2)
	if !bytes.Equal(wrong.auth, []byte{1, 1}) || !bytes.Equal(anonymous.method, []byte{5, 0xff}) || bind.reply != replyCommand {
		t.Fatalf("wrong %+v anonymous %+v bind %+v", wrong, anonymous, bind)
	}
	select {
	case request := <-seen:
		t.Fatalf("the router saw %x", request.header)
	default:
	}
}

func TestNoRouterSocketIsAGeneralFailure(t *testing.T) {
	dir := t.TempDir()
	writeCredential(t, filepath.Join(dir, "ingress-mtproxy.json"), strings.Repeat("p", 32))
	address, _ := startBridge(t, dir, maxConnections)
	if got := socks(t, address, 1, []byte{1, 1, 1, 1}, []byte("x"), "telemt", strings.Repeat("p", 32), []byte{2}, 1); got.reply != replyFailure {
		t.Fatalf("%+v", got)
	}
}

func TestNoCredentialClosesBeforeTheGreetingIsAnswered(t *testing.T) {
	address, _ := startBridge(t, t.TempDir(), maxConnections)
	if check(address, time.Second) {
		t.Fatal("a bridge without the router's credential must not look healthy")
	}
}

func TestANewCredentialIsPickedUpWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ingress-mtproxy.json")
	writeCredential(t, path, strings.Repeat("p", 32))
	fakeRouter(t, filepath.Join(dir, "ingress-mtproxy.sock"))
	address, _ := startBridge(t, dir, maxConnections)
	first := socks(t, address, 1, []byte{1, 1, 1, 1}, []byte("a"), "telemt", strings.Repeat("p", 32), []byte{2}, 1)
	writeCredential(t, path, strings.Repeat("r", 40))
	os.Chtimes(path, time.Unix(0, 1), time.Unix(0, 1))
	old := socks(t, address, 1, []byte{1, 1, 1, 1}, []byte("b"), "telemt", strings.Repeat("p", 32), []byte{2}, 1)
	fresh := socks(t, address, 1, []byte{1, 1, 1, 1}, []byte("c"), "telemt", strings.Repeat("r", 40), []byte{2}, 1)
	if first.reply != 0 || !bytes.Equal(old.auth, []byte{1, 1}) || string(fresh.data) != "C" {
		t.Fatalf("first %+v old %+v new %+v", first, old, fresh)
	}
}

func TestCheckAnswersOnlyALiveListener(t *testing.T) {
	dir := t.TempDir()
	writeCredential(t, filepath.Join(dir, "ingress-mtproxy.json"), strings.Repeat("p", 32))
	b := newBridge(filepath.Join(dir, "ingress-mtproxy.sock"), filepath.Join(dir, "ingress-mtproxy.json"), maxConnections)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	go b.serve(listener)
	address := listener.Addr().String()
	if !check(address, time.Second) {
		t.Fatal("a live bridge must pass the check")
	}
	listener.Close()
	if check(address, 500*time.Millisecond) {
		t.Fatal("a closed listener must fail the check")
	}
}

func TestAFullBridgeClosesNewConnectionsAndFreesSlots(t *testing.T) {
	dir := t.TempDir()
	writeCredential(t, filepath.Join(dir, "ingress-mtproxy.json"), strings.Repeat("p", 32))
	address, _ := startBridge(t, dir, 1)
	holder, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	holder.Write([]byte{5, 1, 2})
	if answer, err := readN(holder, 2); err != nil || answer[1] != 2 {
		t.Fatalf("the first connection must be served: %x %v", answer, err)
	}
	if check(address, time.Second) {
		t.Fatal("a connection over the limit must be closed")
	}
	holder.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !check(address, time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("the slot was not freed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestListenAddressMustBeAnIPAndPort(t *testing.T) {
	for value, ok := range map[string]bool{"": true, "0.0.0.0:45103": true, "127.0.0.1:1": true, "[::1]:45103": true,
		"bridge:45103": false, "45103": false} {
		t.Setenv("XRAY_ROUTER_BRIDGE_LISTEN", value)
		if _, _, err := listenAddress(); (err == nil) != ok {
			t.Fatalf("%q: %v", value, err)
		}
	}
}
