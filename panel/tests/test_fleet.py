from __future__ import annotations

import json
import asyncio
import hashlib
import time

import httpx
import pytest

from panel.fleet import CommandConflict, FleetStore, ProtocolError, TypedCommand
from panel.agent_service import build_executor
from panel.node_agent import AgentJournal, ExecutionIndeterminate, LocalTelemtExecutor, NodeAgent, RoutingExecutor


pytestmark = pytest.mark.anyio


def command(sequence=1, *, operation="telemt.user.disable", payload=None, revision="rev-7"):
    payload = payload if payload is not None else {"username": "alice"}
    payload_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return TypedCommand.parse({
        "protocol_version": 1,
        "command_id": f"018f47ac-1234-7abc-8def-{sequence:012d}",
        "node_id": "edge-01",
        "sequence": sequence,
        "idempotency_key": f"disable-alice-{sequence}",
        "operation": operation,
        "expected_telemt_revision": revision,
        "actor": "owner", "expires_at": int(time.time()) + 60, "payload_sha256": payload_sha256,
        "payload": payload,
    })
































def command_envelope(stored):
    return {key: stored[key] for key in (
        "protocol_version", "command_id", "node_id", "sequence", "idempotency_key", "operation",
        "expected_telemt_revision", "actor", "expires_at", "payload_sha256", "payload",
    )}



























