"""The one network probe the router manager makes on the operator's behalf (v0.8): a TLS
fetch of Cloudflare's trace page through a loopback port a throwaway Xray forwards to the
exit under test. What comes back is what the far end saw — the exit's public address and
the Cloudflare colo that answered — never anything about this host."""
from __future__ import annotations

import http.client
import socket
import ssl

TRACE_PATH = "/cdn-cgi/trace"


def probe_trace(port: int, host: str, timeout: float) -> dict:
    """`{ip, colo}` from the trace page fetched through `127.0.0.1:<port>`; `OSError` (and
    its subclasses, TLS included) when nothing answers or the answer is not the page."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as tls:
            connection = http.client.HTTPConnection(host, timeout=timeout)
            connection.sock = tls
            connection.request("GET", TRACE_PATH, headers={"Host": host, "User-Agent": "proxy-control-exit-probe/0.8", "Connection": "close"})
            response = connection.getresponse()
            body = response.read(4096).decode("utf-8", "replace")
            if response.status != 200:
                raise OSError(f"trace page answered {response.status}")
    finally:
        raw.close()
    fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    if "ip" not in fields:
        raise OSError("trace page had no ip field")
    return {"ip": fields.get("ip", ""), "colo": fields.get("colo", "")}
