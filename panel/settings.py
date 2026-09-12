from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


def _secret_setting(name: str, file_name: str) -> str:
    if os.getenv(file_name):
        return Path(os.environ[file_name]).read_text().strip()
    return os.getenv(name, "")


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path(os.getenv("PANEL_DATABASE", "/data/panel.sqlite3"))
    telemt_url: str = os.getenv("TELEMT_API_URL", "http://mtproxy:9091")
    telemt_token: str = field(
        default_factory=lambda: _secret_setting(
            "TELEMT_API_TOKEN", "TELEMT_API_TOKEN_FILE"
        )
    )
    naive_socket: str = os.getenv(
        "NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock"
    )
    naive_token: str = field(
        default_factory=lambda: _secret_setting(
            "NAIVE_MANAGER_TOKEN", "NAIVE_MANAGER_TOKEN_FILE"
        )
    )
    naive_public_host: str = os.getenv("NAIVE_PUBLIC_HOST", "")
    naive_enabled: bool = os.getenv("NAIVE_ENABLED", "false").lower() == "true"
    mieru_socket: str = os.getenv(
        "MIERU_MANAGER_SOCKET", "/run/mieru-manager/manager.sock"
    )
    mieru_token: str = field(
        default_factory=lambda: _secret_setting(
            "MIERU_MANAGER_TOKEN", "MIERU_MANAGER_TOKEN_FILE"
        )
    )
    mieru_enabled: bool = os.getenv("MIERU_ENABLED", "false").lower() == "true"
    # Which writer serves the protocol endpoints. `legacy` calls the managers directly,
    # exactly as v0.1.0 did; `domain` routes the same requests through clients/grants so
    # the panel owns the credential. Cutover order: import first, then flip this.
    vnext_writer: str = os.getenv("PANEL_VNEXT_WRITER", "legacy")
    # Base of the subscription URL the panel hands out (`https://<subscription domain>`).
    # It is a separate domain from the panel's own, so a subscriber never learns where
    # the panel lives (plan, owner decision 1). Empty means "not published yet".
    subscription_url: str = os.getenv("PANEL_SUBSCRIPTION_URL", "")
    # The only Host `/s/{token}` answers on. Defaults to the URL's own host; empty
    # means the public endpoint is switched off and every `/s/` request is a 404.
    subscription_host: str = os.getenv("PANEL_SUBSCRIPTION_HOST", "").lower()
    version_agent_socket: str = os.getenv(
        "VERSION_AGENT_SOCKET", "/run/proxy-control/version-agent.sock"
    )
    # The release's VERSION file: the repository root in a checkout, /app/VERSION in
    # the image. Absent means the panel reports itself as "dev".
    panel_version_file: Path = Path(
        os.getenv("PANEL_VERSION_FILE", str(Path(__file__).resolve().parent.parent / "VERSION"))
    )
    # Absent means "no secret store": the panel still starts, but only while the
    # database holds no encrypted rows (ADR 005).
    master_key_file: Path | None = field(
        default_factory=lambda: Path(os.environ["PANEL_MASTER_KEY_FILE"])
        if os.getenv("PANEL_MASTER_KEY_FILE")
        else None
    )
    session_cookie_secure: bool = (
        os.getenv("PANEL_COOKIE_SECURE", "true").lower() == "true"
    )
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            filter(
                None, os.getenv("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
            )
        )
    )
    session_ttl_seconds: int = 12 * 3600
    login_attempts: int = 5
    login_window_seconds: int = 300
    reveal_ttl_seconds: int = 120
    body_limit_bytes: int = 65536
    login_verify_concurrency: int = 2
    api_key_rate_per_minute: int = 120

    def __post_init__(self) -> None:
        if not self.subscription_host and self.subscription_url:
            host = (urlsplit(self.subscription_url).hostname or "").lower()
            object.__setattr__(self, "subscription_host", host)
