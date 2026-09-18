from __future__ import annotations

import logging
import os
import signal
import threading
from pathlib import Path

from .intent import PORTS
from .server import ManagerHTTPServer
from .service import ArtifactMismatch, SubprocessXrayRunner, XrayRouterManager

WATCHDOG_SECONDS = 2.0


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or not value.strip():
        raise SystemExit(f"{name} is required")
    return value.strip()


def build_manager() -> XrayRouterManager:
    bin_dir = Path(_env("XRAY_ROUTER_BIN_DIR", "/opt/xray"))
    state_dir = Path(os.getenv("XRAY_ROUTER_STATE_DIR", "/var/lib/xray-router"))
    ports = {"naive": int(os.getenv("XRAY_ROUTER_PORT_NAIVE", str(PORTS["naive"]))),
             "mieru": int(os.getenv("XRAY_ROUTER_PORT_MIERU", str(PORTS["mieru"])))}
    return XrayRouterManager(
        state_dir=state_dir,
        # Xray resolves geosite/geoip codes against the manager's own copy (v0.8): the pinned
        # pair seeds it, updates replace it, the binary directory stays read-only.
        runner=SubprocessXrayRunner(bin_dir / "xray", state_dir / "geodata"),
        ingress_files={"naive": Path(_env("XRAY_ROUTER_INGRESS_NAIVE_FILE", "/run/secrets/xray-router-ingress-naive")),
                       "mieru": Path(_env("XRAY_ROUTER_INGRESS_MIERU_FILE", "/run/secrets/xray-router-ingress-mieru"))},
        # The WARP proxy-mode endpoint the router may send traffic through (v0.4 provider).
        warp_url=os.getenv("XRAY_ROUTER_EGRESS_WARP", "").strip() or None,
        artifacts={"xray": (bin_dir / "xray", _env("XRAY_ROUTER_XRAY_SHA256")),
                   "geoip": (bin_dir / "geoip.dat", _env("XRAY_ROUTER_GEOIP_SHA256")),
                   "geosite": (bin_dir / "geosite.dat", _env("XRAY_ROUTER_GEOSITE_SHA256"))},
        ports=ports,
    )


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    token = Path(_env("XRAY_ROUTER_MANAGER_TOKEN_FILE", "/run/secrets/xray-router-manager-token")).read_text().strip()
    manager = build_manager()
    try:
        manager.bootstrap()
    except ArtifactMismatch as exc:
        # The API still answers (503 with the reason) so the panel can say what is wrong.
        logging.getLogger("xray_router_manager").error("%s", exc)
    server = ManagerHTTPServer(
        Path(os.getenv("XRAY_ROUTER_SOCKET", "/run/xray-router/manager.sock")), manager, token,
        socket_uid=int(os.environ["XRAY_ROUTER_PANEL_UID"]) if os.getenv("XRAY_ROUTER_PANEL_UID") else None,
        socket_mode=int(os.getenv("XRAY_ROUTER_SOCKET_MODE", "660"), 8),
    )
    stop = threading.Event()

    def watchdog() -> None:
        while not stop.wait(WATCHDOG_SECONDS):
            try:
                manager.watchdog_tick()
            except Exception:  # noqa: BLE001 — the watchdog outlives one bad tick
                logging.getLogger("xray_router_manager").warning("watchdog tick failed", exc_info=True)

    thread = threading.Thread(target=watchdog, name="watchdog", daemon=True)
    thread.start()

    def terminate(*_args) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        manager.close()


if __name__ == "__main__":
    main()
