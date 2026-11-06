// SPDX-License-Identifier: Apache-2.0
// Proxy Control's process-wide authenticated CONNECT payload meter.
package forwardproxy

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type liveMeterCapability struct{}

func (liveMeterCapability) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "proxy_control.naive_live_meter", New: func() caddy.Module { return new(liveMeterCapability) }}
}
func init() { caddy.RegisterModule(liveMeterCapability{}) }

var processLive = struct {
	upload, download, active atomic.Uint64
	start                    time.Time
	epoch                    string
	once                     sync.Once
	err                      error
}{start: time.Now(), epoch: newLiveEpoch()}

func newLiveEpoch() string {
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type liveSnapshot struct {
	Schema        uint64 `json:"schema"`
	Semantics     string `json:"semantics"`
	ProcessEpoch  string `json:"process_epoch"`
	SampledAtMS   uint64 `json:"sampled_at_ms"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
	ActiveTunnels uint64 `json:"active_tunnels"`
}

func snapshotLive() liveSnapshot {
	s := liveSnapshot{Schema: 1, Semantics: "authenticated_connect_payload", ProcessEpoch: processLive.epoch,
		UploadBytes: processLive.upload.Load(), DownloadBytes: processLive.download.Load(), ActiveTunnels: processLive.active.Load()}
	s.SampledAtMS = uint64(time.Since(processLive.start).Milliseconds())
	return s
}
func serveLive(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/live" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snapshotLive())
}

// One listener belongs to the process, not to a Caddy config generation. Reload
// must neither reset counters nor stop serving old handlers' live tunnels.
func provisionLiveMeter() error {
	path := os.Getenv("PROXY_CONTROL_NAIVE_LIVE_SOCKET")
	if path == "" {
		return nil
	}
	if path != "/run/caddy-naive/live.sock" {
		return fmt.Errorf("unsupported Naive live socket path")
	}
	processLive.once.Do(func() {
		if st, err := os.Lstat(path); err == nil {
			if st.Mode()&os.ModeSocket == 0 {
				processLive.err = fmt.Errorf("Naive live socket path is not a socket")
				return
			}
			if err = os.Remove(path); err != nil {
				processLive.err = err
				return
			}
		} else if !os.IsNotExist(err) {
			processLive.err = err
			return
		}
		listener, err := net.Listen("unix", path)
		if err != nil {
			processLive.err = err
			return
		}
		if err = os.Chown(path, -1, 101); err == nil {
			err = os.Chmod(path, 0660)
		}
		if err != nil {
			_ = listener.Close()
			processLive.err = err
			return
		}
		server := &http.Server{Handler: http.HandlerFunc(serveLive), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
		go func() { _ = server.Serve(listener) }()
	})
	return processLive.err
}

type liveTunnel struct {
	refs    atomic.Int32
	metered bool
}

func beginLiveTunnel(authenticated bool) *liveTunnel {
	t := &liveTunnel{metered: authenticated}
	t.refs.Store(1)
	if authenticated {
		processLive.active.Add(1)
	}
	return t
}
func (t *liveTunnel) done() {
	if t.refs.Add(-1) == 0 && t.metered {
		processLive.active.Add(^uint64(0))
	}
}

// liveIoCopy counts only bytes accepted by the destination writer. Padding frame
// headers and tail padding are excluded, even on partial writes with an error.
func liveIoCopy(dst io.Writer, src io.Reader, buf []byte, paddingType int, counter *atomic.Uint64) (written int64, err error) {
	var rc *http.ResponseController
	if rw, ok := dst.(http.ResponseWriter); ok {
		rc = http.NewResponseController(rw)
	}
	frames := 0
	for {
		var nr, payloadStart, payloadLen int
		var er error
		if paddingType == AddPadding && frames < NumFirstPaddings {
			frames++
			padding := rand.Intn(256)
			nr, er = src.Read(buf[3 : 65536-3-padding])
			payloadStart, payloadLen = 3, nr
			if nr > 0 {
				buf[0], buf[1], buf[2] = byte(nr/256), byte(nr%256), byte(padding)
				clear(buf[3+nr : 3+nr+padding])
				nr += 3 + padding
			}
		} else if paddingType == RemovePadding && frames < NumFirstPaddings {
			frames++
			_, er = io.ReadFull(src, buf[:3])
			if er != nil {
				if er == io.EOF {
					return written, nil
				}
				return written, er
			}
			payloadLen = int(buf[0])*256 + int(buf[1])
			padding := int64(buf[2])
			nr, er = io.ReadFull(src, buf[:payloadLen])
			if er == nil {
				_, er = io.CopyN(io.Discard, src, padding)
			}
			payloadLen = nr
		} else {
			nr, er = src.Read(buf)
			payloadLen = nr
		}
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nw > nr {
				return written, fmt.Errorf("invalid write count %d", nw)
			}
			written += int64(nw)
			n := nw - payloadStart
			if n > payloadLen {
				n = payloadLen
			}
			if n > 0 && counter != nil {
				counter.Add(uint64(n))
			}
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
			if rc != nil {
				if err = rc.Flush(); err != nil {
					return written, err
				}
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
