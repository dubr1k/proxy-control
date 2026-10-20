"""Authenticated, body-bounded HTTP API on a local Unix socket."""
from __future__ import annotations

import json
import logging
import os
import secrets
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .service import ApiError

LOGGER = logging.getLogger("awg_manager")
CONNECTION_LOST = (BrokenPipeError, ConnectionResetError)
MAX_BODY = 32_768


class ManagerHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path,
        manager,
        token: str,
        *,
        socket_mode: int = 0o660,
    ):
        if len(token) < 32:
            raise ValueError("manager token is too short")
        self.socket_path, self.manager, self.token = Path(socket_path), manager, token
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        super().__init__(str(self.socket_path), ManagerHandler)
        os.chmod(self.socket_path, socket_mode)

    def server_close(self):
        super().server_close()
        self.socket_path.unlink(missing_ok=True)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], CONNECTION_LOST):
            return
        LOGGER.warning("manager request failed", exc_info=True)


class ManagerHandler(BaseHTTPRequestHandler):
    server: ManagerHTTPServer

    def log_message(self, _format, *_args):
        return

    def _send(self, status: int, value=None):
        data = b"" if value is None else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ApiError(422, "invalid_request", "invalid body") from exc
        if not 0 <= length <= MAX_BODY:
            raise ApiError(422, "invalid_request", "invalid body")
        try:
            value = json.loads(self.rfile.read(length)) if length else {}
        except ValueError as exc:
            raise ApiError(422, "invalid_request", "invalid body") from exc
        if not isinstance(value, dict):
            raise ApiError(422, "invalid_request", "invalid body")
        return value

    def _route(self):
        manager = self.server.manager
        cmd = self.command
        path = urlsplit(self.path).path
        if cmd == "GET" and path == "/v1/health":
            return 200, manager.health()
        if cmd == "GET" and path == "/v1/instances":
            return 200, manager.list_instances()
        if cmd == "GET" and path == "/v1/peers":
            return 200, manager.list_peers()
        if cmd == "POST" and path == "/v1/peers":
            return manager.create_peer(self._body())
        if cmd == "GET" and path == "/v1/egress":
            return 200, manager.egress_view()
        if cmd == "POST" and path in ("/v1/egress/plan", "/v1/egress/apply", "/v1/egress/rollback"):
            method = {"plan": manager.egress_plan, "apply": manager.egress_apply,
                      "rollback": manager.egress_rollback}[path.rsplit("/", 1)[1]]
            return 200, method(self._body())
        prefix = "/v1/peers/"
        if path.startswith(prefix):
            tail = path[len(prefix):].split("/")
            username = unquote(tail[0])
            if cmd == "DELETE" and len(tail) == 1:
                manager.delete_peer(username)
                return 204, None
            if cmd == "POST" and len(tail) == 2:
                if tail[1] in ("enable", "disable"):
                    if self._body():
                        raise ApiError(422, "invalid_request", "invalid request fields")
                    return 200, manager.set_enabled(username, tail[1] == "enable")
                if tail[1] == "rotate":
                    return 200, manager.rotate(username, self._body())
        raise ApiError(404, "not_found", "not found")

    def _dispatch(self):
        supplied = self.headers.get("X-Awg-Token", "")
        if not supplied or not secrets.compare_digest(
            supplied.encode(), self.server.token.encode()
        ):
            return self._reply(401, {"detail": "unauthorized", "code": "unauthorized"})
        try:
            status, payload = self._route()
        except ApiError as exc:
            return self._reply(exc.status, {"detail": exc.detail, "code": exc.code})
        except CONNECTION_LOST:
            self.close_connection = True
            return None
        except Exception:  # noqa: BLE001 - never leak internals to the caller
            LOGGER.exception("manager operation failed")
            return self._reply(500, {"detail": "manager operation failed", "code": "internal_error"})
        return self._reply(status, payload)

    def _reply(self, status: int, payload) -> None:
        try:
            self._send(status, payload)
        except CONNECTION_LOST:
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = _dispatch
