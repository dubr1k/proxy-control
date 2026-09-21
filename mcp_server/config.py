"""Configuration of the MCP server (spec §9a), from the environment and the two secret
files the installer writes: the token MCP clients present and the panel API key the
server uses on their behalf."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PANEL_URL = "http://panel:8787"
DEFAULT_PANEL_KEY_FILE = "/run/secrets/mcp-panel-key"
DEFAULT_TOKEN_FILE = "/run/secrets/mcp-token"
DEFAULT_BIND = "0.0.0.0:8793"
MIN_TOKEN_LENGTH = 32


def _read_secret(path: str, variable: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"{variable}: cannot read {path}: {exc.strerror}") from exc
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"{variable}: {path} must hold one non-empty line")
    return value


@dataclass(frozen=True)
class Config:
    panel_url: str
    panel_host: str
    panel_key: str
    token: str
    bind_host: str
    bind_port: int
    allowed_hosts: tuple[str, ...]
    public_url: str

    @classmethod
    def from_env(cls, environ: os._Environ | dict | None = None) -> Config:
        env = os.environ if environ is None else environ
        panel_host = env.get("MCP_PANEL_HOST", "").strip()
        if not panel_host:
            raise ValueError("MCP_PANEL_HOST is required: the panel's allowed host name")
        allowed = tuple(part.strip() for part in env.get("MCP_ALLOWED_HOSTS", "").split(",") if part.strip())
        if not allowed:
            raise ValueError("MCP_ALLOWED_HOSTS is required: the MCP domain and 127.0.0.1:8793, comma separated")
        bind = env.get("MCP_BIND", DEFAULT_BIND).strip()
        host, separator, port = bind.rpartition(":")
        if not separator or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("MCP_BIND must be host:port")
        token = _read_secret(env.get("MCP_TOKEN_FILE", DEFAULT_TOKEN_FILE), "MCP_TOKEN_FILE")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"MCP_TOKEN_FILE: the token must be at least {MIN_TOKEN_LENGTH} characters")
        return cls(
            panel_url=env.get("MCP_PANEL_URL", DEFAULT_PANEL_URL).rstrip("/"),
            panel_host=panel_host,
            panel_key=_read_secret(env.get("MCP_PANEL_KEY_FILE", DEFAULT_PANEL_KEY_FILE), "MCP_PANEL_KEY_FILE"),
            token=token,
            bind_host=host,
            bind_port=int(port),
            allowed_hosts=allowed,
            public_url=env.get("MCP_PUBLIC_URL", "").strip(),
        )
