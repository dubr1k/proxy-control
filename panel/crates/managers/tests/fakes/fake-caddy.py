#!/usr/bin/python3
"""Fake Caddy for the naive-manager contract tests: the admin API on 127.0.0.1:2019 (/adapt, /load)
and a TLS cover site on 127.0.0.1:4443, inside the test's own network namespace. Exits when its
parent (the manager) is gone. Usage: fake-caddy.py CERT KEY"""
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def forward_proxy_handlers(text):
    handlers, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        if not re.fullmatch(r"\s*forward_proxy\s*\{\s*(#.*)?", lines[i]):
            i += 1
            continue
        depth = lines[i].count("{") - lines[i].count("}")
        credentials, upstream, deny = 0, None, []
        i += 1
        while i < len(lines) and depth > 0:
            line = lines[i].strip()
            depth += line.count("{") - line.count("}")
            if re.fullmatch(r"basic_auth\s+\S+\s+\S+", line):
                credentials += 1
            match = re.match(r"upstream\s+(\S+)", line)
            if match:
                upstream = match.group(1)
            match = re.match(r"deny\s+(.+)", line)
            if match:
                deny.extend(match.group(1).split())
            i += 1
        handler = {"handler": "forward_proxy", "auth_credentials": ["opaque"] * credentials}
        if upstream is not None:
            handler["upstream"] = upstream
        if deny:
            handler["acl"] = [{"subjects": deny, "allow": False}]
        handlers.append(handler)
    return handlers


class Admin(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        path = self.path.split("?")[0]
        if path == "/adapt":
            handlers = forward_proxy_handlers(body.decode("utf-8"))
            config = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{"handle": handlers}]}}}}}
            return self.reply(200, json.dumps({"result": config, "warnings": []}).encode())
        if path == "/load":
            json.loads(body)
            return self.reply(200, b"")
        return self.reply(404, b"{}")


def answer(context, connection):
    try:
        connection.settimeout(5)
        with context.wrap_socket(connection, server_side=True) as tls:
            tls.recv(4096)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        connection.close()


def cover(listener, context):
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=answer, args=(context, connection), daemon=True).start()


def watch_parent(parent):
    while os.getppid() == parent:
        time.sleep(0.5)
    os._exit(0)


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    listener = socket.create_server(("127.0.0.1", 4443))
    admin = ThreadingHTTPServer(("127.0.0.1", 2019), Admin)
    threading.Thread(target=cover, args=(listener, context), daemon=True).start()
    threading.Thread(target=watch_parent, args=(os.getppid(),), daemon=True).start()
    admin.serve_forever()
