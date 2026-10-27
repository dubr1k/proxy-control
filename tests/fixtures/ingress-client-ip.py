"""Run real isolated Nginx using files rendered by the native installer test."""
from __future__ import annotations

import http.server
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
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
    assert b"200 OK" in result, result
    return result.split(b"\r\n\r\n", 1)[1]


def main(root):
    key, cert = root / "key.pem", root / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=panel.example.com", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True, timeout=20)
    upstream = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    raw_backend = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    raw_backend.socket = tls.wrap_socket(raw_backend.socket, server_side=True)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (upstream, raw_backend)]
    for thread in threads:
        thread.start()
    public, private = unused_port(), unused_port()
    stream = (root / "stream.conf").read_text().replace("listen 443;", f"listen 127.0.0.1:{public};")
    stream = stream.replace("127.0.0.1:8445", f"127.0.0.1:{raw_backend.server_port}")
    vhost = (root / "panel.conf").read_text().replace("127.0.0.1:8443", f"127.0.0.1:{private}")
    vhost = vhost.replace("127.0.0.1:8787", f"127.0.0.1:{upstream.server_port}")
    vhost = vhost.replace("/etc/letsencrypt/live/relay.example.com/fullchain.pem", str(cert))
    vhost = vhost.replace("/etc/letsencrypt/live/relay.example.com/privkey.pem", str(key))
    config = ("load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
              + ("user root;\n" if os.geteuid() == 0 else "")
              + f"pid {root}/nginx.pid; error_log {root}/error.log;\n"
              + f"events {{}}\nhttp {{ access_log off; {vhost} }}\nstream {{ {stream} }}\n")
    config = config.replace("/run/proxy-control-", str(root / "pc-"))
    path = root / "nginx.conf"
    path.write_text(config)
    process = None
    try:
        checked = subprocess.run(["nginx", "-t", "-p", str(root), "-c", str(path)], capture_output=True, timeout=10)
        assert checked.returncode == 0, checked.stderr.decode()
        process = subprocess.Popen(["nginx", "-p", str(root), "-c", str(path), "-g", "daemon off;"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while True:
            assert process.poll() is None, (root / "error.log").read_text()
            try:
                with socket.create_connection(("127.0.0.1", public), timeout=0.1):
                    break
            except OSError:
                assert time.monotonic() < deadline, "isolated Nginx failed to bind"
                time.sleep(0.02)
        assert request(public, "panel.example.com", "127.0.0.2") == b"127.0.0.2"
        assert request(public, "panel.example.com", "127.0.0.3") == b"127.0.0.3"
        assert request(private, "panel.example.com", "127.0.0.4") == b"127.0.0.4"
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


if __name__ == "__main__":
    main(Path(sys.argv[1]))
