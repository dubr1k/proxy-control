"""Authenticated, body-bounded HTTP API on a local Unix socket (the panel's only door)."""
from __future__ import annotations

import json
import logging
import os
import secrets
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

from .intent import SERVICES, EgressInvalid, EgressUnreachable
from .service import ArtifactMismatch, ManagerConflict, ManualInterventionRequired, ValidationError, XrayError

LOGGER = logging.getLogger("xray_router_manager")
CONNECTION_LOST = (BrokenPipeError, ConnectionResetError)
TOKEN_HEADER = "X-Xray-Router-Token"


class ManagerHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: Path, manager, token: str, *, socket_uid: int | None = None,
                 socket_mode: int = 0o600):
        if len(token) < 32:
            raise ValueError("manager token is too short")
        self.socket_path, self.manager, self.token = Path(socket_path), manager, token
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        super().__init__(str(self.socket_path), ManagerHandler)
        os.chmod(self.socket_path, socket_mode)
        if socket_uid is not None:
            os.chown(self.socket_path, socket_uid, -1)

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
            raise ValidationError("invalid body") from exc
        if not 0 <= length <= 32_768:
            raise ValidationError("invalid body")
        try:
            value = json.loads(self.rfile.read(length)) if length else {}
        except ValueError as exc:
            raise ValidationError("invalid body") from exc
        if not isinstance(value, dict):
            raise ValidationError("invalid body")
        return value

    @staticmethod
    def _exact(body: dict, required: set[str]):
        if set(body) != required:
            raise ValidationError("invalid request fields")

    def _dispatch(self):
        supplied = self.headers.get(TOKEN_HEADER, "")
        if not supplied or not secrets.compare_digest(supplied, self.server.token):
            return self._send(401, {"detail": "unauthorized"})
        path = urlsplit(self.path).path
        manager = self.server.manager
        try:
            if self.command == "GET" and path in ("/v1/health", "/healthz"):
                status = manager.status()
                if status["artifact_error"] or status["phase"] == "broken":
                    return self._send_error(503, {"detail": status["artifact_error"] or "router is broken",
                                                  "code": "artifact_mismatch" if status["artifact_error"] else "manual_intervention_required"})
                return self._send(200 if status["running"] else 503, {"ready": status["running"] is not None})
            if self.command == "GET" and path == "/v1/status":
                status = manager.status()
                return self._send(503 if status["artifact_error"] else 200, status)
            prefix = "/v1/egress/"
            if path.startswith(prefix):
                tail = path[len(prefix):].split("/")
                service = tail[0]
                if service not in SERVICES:
                    return self._send(404, {"detail": "not found"})
                if self.command == "GET" and len(tail) == 1:
                    return self._send(200, manager.egress(service))
                if self.command == "POST" and len(tail) == 2:
                    body = self._body()
                    if tail[1] == "plan":
                        self._exact(body, {"expected_revision", "document"})
                        return self._send(200, manager.egress_plan(service, body["expected_revision"], body["document"]))
                    if tail[1] == "apply":
                        self._exact(body, {"expected_revision", "document", "operation_id"})
                        return self._send(200, manager.egress_apply(service, body["expected_revision"], body["document"],
                                                                    body["operation_id"]))
                    if tail[1] == "rollback":
                        self._exact(body, {"expected_revision"})
                        return self._send(200, manager.egress_rollback(service, body["expected_revision"]))
            return self._send(404, {"detail": "not found"})
        except CONNECTION_LOST:
            self.close_connection = True
        except EgressInvalid as exc:
            return self._send_error(422, {"detail": str(exc)[:400], "code": exc.code})
        except EgressUnreachable as exc:
            return self._send_error(409, {"detail": str(exc), "code": "egress_unreachable"})
        except ManagerConflict as exc:
            return self._send_error(409, {"detail": str(exc), "code": exc.code})
        except ValidationError:
            return self._send_error(422, {"detail": "invalid request"})
        except ArtifactMismatch as exc:
            return self._send_error(503, {"detail": str(exc), "code": "artifact_mismatch"})
        except ManualInterventionRequired as exc:
            return self._send_error(503, {"detail": str(exc)[:400], "code": "manual_intervention_required"})
        except XrayError as exc:
            return self._send_error(502, {"detail": str(exc)[:400], "code": "egress_readback_mismatch"})

    def _send_error(self, status: int, payload: dict) -> None:
        try:
            self._send(status, payload)
        except CONNECTION_LOST:
            self.close_connection = True

    do_GET = do_POST = _dispatch
