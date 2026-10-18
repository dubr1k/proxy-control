from __future__ import annotations

import logging
import os
import signal
import threading

from .config import ConfigError, from_env
from .server import ManagerHTTPServer
from .service import TrusttunnelManager
from .supervisor import ProcessSupervisor

LOGGER = logging.getLogger("trusttunnel_manager")
TICK_SECONDS = 1.0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = from_env(os.environ)
    token = config.token_file.read_text().strip()
    if not 32 <= len(token) <= 512:
        raise ConfigError("API token must be 32-512 characters")
    manager = TrusttunnelManager(config, ProcessSupervisor(config.binary))
    stop = threading.Event()
    server = None
    try:
        manager.bootstrap()
        server = ManagerHTTPServer(config.socket, manager, token, socket_mode=config.socket_mode)
        serve(manager, server, stop)
    finally:
        stop.set()
        if server is not None:
            server.server_close()
        manager.shutdown()


def serve(manager: TrusttunnelManager, server: ManagerHTTPServer, stop: threading.Event) -> None:
    def supervise() -> None:
        while not stop.wait(TICK_SECONDS):
            try:
                manager.tick()
            except Exception:  # noqa: BLE001 - the supervisor loop must survive
                LOGGER.exception("supervision tick failed")

    threading.Thread(target=supervise, name="supervisor", daemon=True).start()

    def on_signal(_signum, _frame) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    server.serve_forever()


if __name__ == "__main__":
    main()
