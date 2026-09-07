import http.server
import ssl
import subprocess
import threading
import pytest
from installer.three_xui_api import ThreeXuiClient, ThreeXuiApiError


def test_panel_client_uses_tls_and_pins_certificate_before_credentials(tmp_path):
    certs = []
    for name in ("server", "wrong"):
        cert = tmp_path / (name + ".crt")
        key = tmp_path / (name + ".key")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
        )
        certs.append((cert, key))
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*map(str, certs[0]))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        good = ThreeXuiClient(port=server.server_port, certificate=certs[0][0])
        assert (
            good.request("GET", "/", body=None, headers={"Authorization": "synthetic"})[
                0
            ]
            == 200
        )
        wrong = ThreeXuiClient(port=server.server_port, certificate=certs[1][0])
        with pytest.raises(ThreeXuiApiError):
            wrong.request(
                "GET", "/", body=None, headers={"Authorization": "MUST-NOT-SEND"}
            )
        assert requests == ["synthetic"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
