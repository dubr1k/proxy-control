"""Real isolated Nginx: client IP survives shared SNI while raw TLS protocols still work."""
import http.server
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import pytest

from installer.adapters.core import _panel_vhost_text
from installer.adapters.nginx import _render_fresh
from panel.agent_transport import CertificateAuthority

MODULE = Path("/usr/lib/nginx/modules/ngx_stream_module.so")
pytestmark = pytest.mark.skipif(not shutil.which("nginx") or not MODULE.exists(), reason="host Nginx stream module required")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = self.headers.get("X-Forwarded-For", "raw-tls-ok").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, host, source):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=3, source_address=(source, 0)) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n".encode())
            result = b""
            while data := tls.recv(4096):
                result += data
    assert b"200 OK" in result
    return result.split(b"\r\n\r\n", 1)[1]


def test_real_shared_ingress_preserves_ip_rejects_spoofed_xff_and_keeps_raw_tls(tmp_path):
    ca = CertificateAuthority(tmp_path / "ca")
    ca.initialize("synthetic ingress CA")
    key, cert = ca.issue_server("panel.example.com", ["panel.example.com", "naive.example.com"])
    upstream = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    raw_backend = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    raw_backend.socket = tls.wrap_socket(raw_backend.socket, server_side=True)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (upstream, raw_backend)]
    for thread in threads:
        thread.start()
    public, private = unused_port(), unused_port()
    stream = _render_fresh({"client_ip": "proxy", "panel_tls_backend": f"127.0.0.1:{private}", "routes": (
        ("naive.example.com", f"127.0.0.1:{raw_backend.server_port}"),
        ("panel.example.com", f"127.0.0.1:{private}"),
    )}).decode().replace("listen 443;", f"listen 127.0.0.1:{public};")
    vhost = _panel_vhost_text(panel_domain="panel.example.com", certificate="synthetic",
                             app_port=upstream.server_port, tls_port=private)
    vhost = vhost.replace("/etc/letsencrypt/live/synthetic/fullchain.pem", str(cert))
    vhost = vhost.replace("/etc/letsencrypt/live/synthetic/privkey.pem", str(key))
    # The test owns a temporary prefix and random TCP ports; it never reloads host Nginx.
    config = (f"load_module {MODULE};\n" + ("user root;\n" if os.geteuid() == 0 else "")
              + f"pid {tmp_path}/nginx.pid; error_log {tmp_path}/error.log;\n"
              + f"events {{}}\nhttp {{ access_log off; {vhost} }}\nstream {{ {stream} }}\n")
    config = config.replace("/run/proxy-control-", str(tmp_path / "pc-"))
    path = tmp_path / "nginx.conf"
    path.write_text(config)
    process = None
    try:
        checked = subprocess.run(["nginx", "-t", "-p", str(tmp_path), "-c", str(path)], capture_output=True)
        assert checked.returncode == 0, checked.stderr.decode()
        process = subprocess.Popen(["nginx", "-p", str(tmp_path), "-c", str(path), "-g", "daemon off;"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", public), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        assert request(public, "panel.example.com", "127.0.0.2") == b"127.0.0.2"
        assert request(public, "panel.example.com", "127.0.0.3") == b"127.0.0.3"
        assert request(private, "panel.example.com", "127.0.0.4") == b"127.0.0.4"
        # The raw TLS backend sees a valid handshake and its own HTTP request, no PROXY bytes.
        assert request(public, "naive.example.com", "127.0.0.2") == b"203.0.113.7"
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=5)
        for server in (upstream, raw_backend):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
