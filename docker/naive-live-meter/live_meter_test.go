package forwardproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shortMeterWriter struct {
	n   int
	err error
}

func (w shortMeterWriter) Write(p []byte) (int, error) {
	if w.n < len(p) {
		return w.n, w.err
	}
	return len(p), w.err
}
func TestLiveMeterPayloadWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		padding int
		n       int
		want    uint64
	}{
		{"plain", NoPadding, 5, 5}, {"padded-header", AddPadding, 2, 0}, {"padded-partial-payload", AddPadding, 5, 2}, {"padded-complete", AddPadding, 65536, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Uint64
			_, _ = liveIoCopy(shortMeterWriter{tc.n, errors.New("partial")}, bytes.NewBufferString("hello"), make([]byte, 65536), tc.padding, &count)
			if got := count.Load(); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
func TestLiveMeterDepaddingAndTruncatedHeader(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		want uint64
	}{
		{[]byte{0, 3, 2, 'a', 'b', 'c', 0, 0}, 3}, {[]byte{0}, 0}, {[]byte{0, 3}, 0},
	} {
		var count atomic.Uint64
		_, _ = liveIoCopy(io.Discard, bytes.NewReader(tc.wire), make([]byte, 65536), RemovePadding, &count)
		if count.Load() != tc.want {
			t.Fatalf("got %d want %d", count.Load(), tc.want)
		}
	}
}
func TestLiveMeterUnpaddedAfterEightFrames(t *testing.T) {
	wire := []byte{}
	for i := 0; i < 8; i++ {
		wire = append(wire, 0, 1, 1, 'x', 0)
	}
	wire = append(wire, []byte("rest")...)
	var count atomic.Uint64
	_, err := liveIoCopy(io.Discard, bytes.NewReader(wire), make([]byte, 65536), RemovePadding, &count)
	if err != nil || count.Load() != 12 {
		t.Fatalf("count=%d err=%v", count.Load(), err)
	}
}

type meterConn struct {
	io.Reader
	io.Writer
}

func (c meterConn) Close() error                     { return nil }
func (c meterConn) LocalAddr() net.Addr              { return nil }
func (c meterConn) RemoteAddr() net.Addr             { return nil }
func (c meterConn) SetDeadline(time.Time) error      { return nil }
func (c meterConn) SetReadDeadline(time.Time) error  { return nil }
func (c meterConn) SetWriteDeadline(time.Time) error { return nil }

type blockedMeterReader struct{ release chan struct{} }

func (r blockedMeterReader) Read([]byte) (int, error) { <-r.release; return 0, io.EOF }
func (r blockedMeterReader) Close() error             { return nil }
func waitMeter(t *testing.T, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for processLive.active.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("active=%d want %d", processLive.active.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestLiveMeterBothDirectionsLifetime(t *testing.T) {
	base := processLive.active.Load()
	tunnel := beginLiveTunnel(true)
	release := make(chan struct{})
	conn := meterConn{bytes.NewReader(nil), io.Discard}
	if err := dualStream(conn, blockedMeterReader{release}, io.Discard, false, tunnel); err != nil {
		t.Fatal(err)
	}
	tunnel.done()
	if processLive.active.Load() != base+1 {
		t.Fatal("tunnel closed before upload goroutine")
	}
	close(release)
	waitMeter(t, base)
}
func TestLiveMeterUnauthenticatedTunnelExcluded(t *testing.T) {
	before := snapshotLive()
	tunnel := beginLiveTunnel(false)
	_ = dualStream(meterConn{bytes.NewBufferString("download"), io.Discard}, io.NopCloser(bytes.NewBufferString("upload")), io.Discard, false, tunnel)
	tunnel.done()
	waitMeter(t, before.ActiveTunnels)
	if processLive.upload.Load() != before.UploadBytes || processLive.download.Load() != before.DownloadBytes {
		t.Fatal("unauthenticated traffic counted")
	}
}
func TestLiveMeterCoverAndRejectedAuthExcluded(t *testing.T) {
	before := snapshotLive()
	h := Handler{AuthCredentials: [][]byte{[]byte("dXNlcjpwYXNz")}, Hosts: caddyhttp.MatchHost{"cover.invalid"}}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { _, _ = w.Write([]byte("cover")); return nil })
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		req := httptest.NewRequest(method, "https://cover.invalid/", nil)
		req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil && method != http.MethodConnect {
			t.Fatal(err)
		}
	}
	after := snapshotLive()
	if before.UploadBytes != after.UploadBytes || before.DownloadBytes != after.DownloadBytes || before.ActiveTunnels != after.ActiveTunnels {
		t.Fatal("cover or rejected CONNECT changed meter")
	}
}
func TestLiveMeterFastOpenDialFailureExcluded(t *testing.T) {
	before := snapshotLive()
	h := Handler{AuthCredentials: [][]byte{[]byte("dXNlcjpwYXNz")}, upstream: &url.URL{Scheme: "socks5", Host: "unused"}, dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("synthetic dial failure")
	}}
	req := httptest.NewRequest(http.MethodConnect, "http://target.invalid:443", nil)
	req.ProtoMajor = 2
	req.URL = &url.URL{Host: "target.invalid:443"}
	req.Host = "target.invalid:443"
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	w := httptest.NewRecorder()
	if h.ServeHTTP(w, req, nil) == nil {
		t.Fatal("expected failed dial")
	}
	if w.Code != 200 {
		t.Fatal("fixture did not take Fast Open branch")
	}
	after := snapshotLive()
	if before.UploadBytes != after.UploadBytes || before.DownloadBytes != after.DownloadBytes || before.ActiveTunnels != after.ActiveTunnels {
		t.Fatal("failed dial counted")
	}
}
func TestLiveMeterReadOnlyEndpoint(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/v1/live", 200}, {"POST", "/v1/live", 405}, {"GET", "/", 404}} {
		w := httptest.NewRecorder()
		serveLive(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("got %d", w.Code)
		}
		if tc.status == 200 {
			var s liveSnapshot
			if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil || s.Schema != 1 || s.Semantics != "authenticated_connect_payload" || s.ProcessEpoch == "" {
				t.Fatal("invalid schema", err)
			}
		}
	}
}

type hijackMeterWriter struct {
	conn   net.Conn
	brw    *bufio.ReadWriter
	header http.Header
}

func (w *hijackMeterWriter) Header() http.Header                          { return w.header }
func (w *hijackMeterWriter) Write(p []byte) (int, error)                  { return len(p), nil }
func (w *hijackMeterWriter) WriteHeader(int)                              {}
func (w *hijackMeterWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, w.brw, nil }
func TestLiveMeterH1BufferedPartialWrite(t *testing.T) {
	before := snapshotLive()
	reader := bufio.NewReader(bytes.NewBufferString("buffered"))
	_, _ = reader.Peek(8)
	w := &hijackMeterWriter{conn: meterConn{bytes.NewReader(nil), io.Discard}, brw: bufio.NewReadWriter(reader, bufio.NewWriter(io.Discard)), header: make(http.Header)}
	tunnel := beginLiveTunnel(true)
	err := serveHijack(w, meterConn{bytes.NewReader(nil), shortMeterWriter{3, io.ErrClosedPipe}}, tunnel)
	tunnel.done()
	if err != io.ErrClosedPipe || processLive.upload.Load()-before.UploadBytes != 3 {
		t.Fatalf("err=%v upload=%d", err, processLive.upload.Load()-before.UploadBytes)
	}
	waitMeter(t, before.ActiveTunnels)
}
func TestLiveMeterH2AuthenticatedPayload(t *testing.T) {
	before := snapshotLive()
	h := Handler{AuthCredentials: [][]byte{[]byte("dXNlcjpwYXNz")}, upstream: &url.URL{Scheme: "socks5", Host: "unused"}, dialContext: func(context.Context, string, string) (net.Conn, error) {
		return meterConn{bytes.NewBufferString("download"), io.Discard}, nil
	}}
	req := httptest.NewRequest(http.MethodConnect, "http://target.invalid:443", bytes.NewBufferString("upload"))
	req.ProtoMajor = 2
	req.URL = &url.URL{Host: "target.invalid:443"}
	req.Host = "target.invalid:443"
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, req, nil); err != nil {
		t.Fatal(err)
	}
	waitMeter(t, before.ActiveTunnels)
	after := snapshotLive()
	if after.UploadBytes-before.UploadBytes != 6 || after.DownloadBytes-before.DownloadBytes != 8 || w.Body.String() != "download" {
		t.Fatalf("bad payload deltas: %d/%d body=%q", after.UploadBytes-before.UploadBytes, after.DownloadBytes-before.DownloadBytes, w.Body.String())
	}
	if after.ProcessEpoch != before.ProcessEpoch || after.SampledAtMS < before.SampledAtMS {
		t.Fatal("process identity or monotonic timestamp changed")
	}
}
func TestLiveMeterParallelHandlersShareProcessCounters(t *testing.T) {
	before := snapshotLive()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tunnel := beginLiveTunnel(true)
			_ = dualStream(meterConn{bytes.NewBufferString("d"), io.Discard}, io.NopCloser(bytes.NewBufferString("u")), io.Discard, false, tunnel)
			tunnel.done()
		}()
	}
	wg.Wait()
	waitMeter(t, before.ActiveTunnels)
	after := snapshotLive()
	if after.UploadBytes-before.UploadBytes != 16 || after.DownloadBytes-before.DownloadBytes != 16 || after.ProcessEpoch != before.ProcessEpoch {
		t.Fatal("handlers did not share process counters")
	}
}
