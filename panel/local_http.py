"""One TLS context for the panel's HTTP clients.

httpx builds a fresh default context — the whole CA bundle loaded from disk — for every
transport it creates, even one that talks plain HTTP over a Unix socket. The manager
clients open a transport per request and the monitor polls every manager once a second,
so that load was most of the panel's idle CPU. An `ssl.SSLContext` is safe to share
between connections; this one is exactly httpx's default (its CA bundle, peer and hostname
verified), built once.
"""
from __future__ import annotations

import functools
import ssl

import httpx


@functools.cache
def tls_context() -> ssl.SSLContext:
    return httpx.create_ssl_context()


def uds_transport(socket_path: str) -> httpx.AsyncHTTPTransport:
    return httpx.AsyncHTTPTransport(uds=socket_path, verify=tls_context())
