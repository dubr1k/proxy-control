"""`python -m mcp_server`: serve `/mcp` and `/healthz` with uvicorn on `MCP_BIND`."""
from __future__ import annotations

import logging
import sys

import uvicorn

from .config import Config
from .server import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        config = Config.from_env()
    except ValueError as exc:
        print(f"proxy-control-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    uvicorn.run(create_app(config), host=config.bind_host, port=config.bind_port, log_level="info",
                proxy_headers=False, server_header=False, date_header=False, access_log=False)


if __name__ == "__main__":
    main()
