from __future__ import annotations

import json
import logging
import os
import signal
import threading

from . import obfuscation
from .config import ConfigError, from_env
from .host import RealHost
from .server import ManagerHTTPServer
from .service import AwgManager

LOGGER = logging.getLogger("awg_manager")
TICK_SECONDS = 1.0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = from_env(os.environ)
    token = config.token_file.read_text().strip()
    if not 32 <= len(token) <= 512:
        raise ConfigError("API token must be 32-512 characters")
    overrides = {}
    if config.obfuscation_file is not None:
        overrides = obfuscation.load_overrides(json.loads(config.obfuscation_file.read_text()))
    manager = AwgManager(config, RealHost(), overrides=overrides)
    stop = threading.Event()
    server = None
    try:
        manager.bootstrap()
        server = ManagerHTTPServer(config.socket, manager, token, socket_mode=config.socket_mode)
        serve(manager, server, stop)
    finally:
        # Whatever failed after the data plane came up, do not leave it behind.
        stop.set()
        if server is not None:
            server.server_close()
        manager.shutdown()


def serve(manager: AwgManager, server: ManagerHTTPServer, stop: threading.Event) -> None:
    def supervise() -> None:
        while not stop.wait(TICK_SECONDS):
            manager.tick()

    threading.Thread(target=supervise, name="supervisor", daemon=True).start()

    def on_signal(_signum, _frame) -> None:
        # shutdown() blocks until serve_forever() returns, so it cannot run in the handler.
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    server.serve_forever()


if __name__ == "__main__":
    main()
