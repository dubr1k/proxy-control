#!/usr/bin/python3
"""Fake `xray` for the xray-router-manager contract tests: `version`, `x25519`, `run -test -config`
and a long-running `run -config` that opens the configured loopback/unix listeners and dies with
the manager."""
import base64
import json
import os
import select
import signal
import socket
import sys


def key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


args = sys.argv[1:]
if args[:1] == ["version"]:
    print("Xray 26.3.27 (Xray, Penetrates Everything.) fake")
    sys.exit(0)
if args[:1] == ["x25519"]:
    print("PrivateKey: " + key())
    print("Password (PublicKey): " + key())
    print("Hash32: x")
    sys.exit(0)
if args[:2] == ["run", "-test"]:
    with open(args[3]) as f:
        json.load(f)
    print("Configuration OK.")
    sys.exit(0)
if args[:2] == ["run", "-config"]:
    with open(args[2]) as f:
        config = json.load(f)
    listeners = []
    for inbound in config.get("inbounds", []):
        listen, port = inbound.get("listen"), inbound.get("port") or 0
        if isinstance(listen, str) and listen.startswith("/"):
            try:
                os.unlink(listen)
            except FileNotFoundError:
                pass
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(listen)
        elif listen == "127.0.0.1" and port:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((listen, port))
        else:
            continue
        s.listen(64)
        listeners.append(s)
    parent = os.getppid()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while os.getppid() == parent:
        ready, _, _ = select.select(listeners, [], [], 1.0)
        for s in ready:
            try:
                conn, _ = s.accept()
                conn.close()
            except OSError:
                pass
    sys.exit(0)
sys.exit(2)
