"""Records what the Python protocol adapters do in their own unit tests (WP6 goldens).

A pytest plugin: every adapter (`panel/protocols/*.py`) a test builds is instrumented, and for each
top-level adapter call the transcript keeps the arguments, the result (or the error) and, per client
object the adapter talks to, every client call with its arguments and its answer (or the error the
fake raised). The Rust tests (`tests/transcripts.rs`) replay each transcript: the same adapter calls
against replaying clients that check every call the Rust adapter makes and hand back the recorded
answer, then compare the results. Nested adapter calls (the Telemt adapter asking the router adapter)
are not recorded as calls: the Rust adapter makes them itself, and their client calls are in the
transcript.

Run on ams-test from the stand copy (needs the panel venv):

    cd /root/dev/rust-panel-wp6 && TRANSCRIPTS=panel/crates/protocols/tests/fixtures/transcripts.json \
        PYTHONPATH=panel/crates/protocols/tests/fixtures:. /root/dev/proxy-control/.venv/bin/python -m pytest \
        -q -p record_transcripts -p no:cacheprovider $(cat panel/crates/protocols/tests/fixtures/transcript-tests.txt)
"""
from __future__ import annotations

import base64
import contextvars
import copy
import dataclasses
import functools
import inspect
import json
import os
from pathlib import Path

import pydantic
import pytest

from panel.protocols import (
    AdapterError,
    AmneziawgAdapter,
    ManualInterventionRequired,
    MieruAdapter,
    NaiveAdapter,
    RouterAdapter,
    TelemtAdapter,
    TrusttunnelAdapter,
)
from panel.telemt import TelemtIndeterminate

ADAPTERS = {
    NaiveAdapter: ("discover", "preflight", "create", "enable", "disable", "rotate", "delete", "update_options",
                   "capture", "render_artifacts", "egress_target", "plan_egress", "apply_egress", "rollback_egress",
                   "lanes", "set_lanes"),
    MieruAdapter: ("discover", "preflight", "create", "enable", "disable", "rotate", "delete", "share", "capture",
                   "update_options", "render_artifacts", "egress_target", "plan_egress", "apply_egress",
                   "rollback_egress", "lanes", "set_lanes"),
    AmneziawgAdapter: ("versions", "discover", "preflight", "create", "enable", "disable", "rotate", "delete",
                       "capture", "update_options", "render_artifacts", "egress_target", "plan_egress",
                       "apply_egress", "rollback_egress"),
    TrusttunnelAdapter: ("endpoint", "discover", "preflight", "create", "enable", "disable", "rotate", "delete",
                         "capture", "update_options", "render_artifacts", "egress_target", "plan_egress",
                         "apply_egress", "rollback_egress"),
    TelemtAdapter: ("discover", "preflight", "create", "enable", "disable", "rotate", "update_options", "delete",
                    "capture", "render_artifacts", "egress_target", "plan_egress", "apply_egress",
                    "rollback_egress"),
    RouterAdapter: ("target", "ingress", "status", "plan", "apply", "rollback", "lanes", "lane_issue",
                    "lane_forget", "relay", "relay_enable", "relay_disable", "relay_set_accounts", "exit_test",
                    "geodata"),
}

DEPTH = contextvars.ContextVar("wp6_depth", default=0)
STATE: dict = {}


def _reset(test: str) -> None:
    STATE.update(test=test, calls=[], clients={}, probes={}, ids={}, counters={"A": 0, "C": 0})


def _ident(obj, prefix: str) -> str:
    key = id(obj)
    if key not in STATE["ids"]:
        STATE["counters"][prefix] += 1
        STATE["ids"][key] = (f"{prefix}{STATE['counters'][prefix]}", obj)  # keep obj alive: ids stay unique
    return STATE["ids"][key][0]


def enc(value):
    """A JSON form of an argument or a result that says what Python type it had."""
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode()}
    if isinstance(value, pydantic.BaseModel):
        return {"$model": type(value).__name__, "data": value.model_dump(mode="json")}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {"$dc": type(value).__name__,
                **{field.name: enc(getattr(value, field.name)) for field in dataclasses.fields(value)}}
    if isinstance(value, (set, frozenset)):
        return sorted(enc(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [enc(item) for item in value]
    if isinstance(value, dict):
        return {str(key): enc(item) for key, item in value.items()}
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return {"$repr": repr(value)}


def enc_error(error: BaseException) -> dict:
    out = {"class": type(error).__name__, "message": str(error),
           "adapter_error": isinstance(error, AdapterError),
           "manual": isinstance(error, ManualInterventionRequired),
           "indeterminate": isinstance(error, TelemtIndeterminate)}
    for attribute in ("status_code", "code", "already_gone"):
        if hasattr(error, attribute):
            out[attribute] = enc(getattr(error, attribute))
    return out


class RecordingClient:
    """Stands in front of the client an adapter holds; every coroutine call is recorded."""

    def __init__(self, target, client_id):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_client_id", client_id)

    def __getattr__(self, name):
        attribute = getattr(self._target, name)
        if name.startswith("_") or name == "batch" or not inspect.iscoroutinefunction(attribute):
            return attribute

        @functools.wraps(attribute)
        async def recorded(*args, **kwargs):
            event = {"method": name, "args": enc(list(args)), "kwargs": enc(kwargs)}
            STATE["clients"].setdefault(self._client_id, []).append(event)
            try:
                result = await attribute(*args, **kwargs)
            except BaseException as error:
                event["error"] = enc_error(error)
                raise
            event["result"] = enc(copy.deepcopy(result))
            return result

        return recorded

    def __setattr__(self, name, value):
        setattr(self._target, name, value)


def _wrap_client(adapter) -> None:
    client = adapter.__dict__.get("client")
    if client is None or isinstance(client, RecordingClient):
        return
    adapter.__dict__["client"] = RecordingClient(client, _ident(client, "C"))


def _state(adapter) -> dict:
    """What the Rust adapter is built from (taken at each call: tests set attributes after __init__)."""
    client = adapter.__dict__["client"]
    state = {"class": type(adapter).__name__, "client": client._client_id}
    for name in ("public_host", "public_port", "port", "reload_timeout", "reload_poll"):
        if name in adapter.__dict__:
            state[name] = enc(adapter.__dict__[name])
    if "router" in adapter.__dict__:
        router = adapter.__dict__["router"]
        state["router"] = None if router is None else _ident(router, "A")
        if router is not None:
            _wrap_client(router)
            state["router_client"] = router.__dict__["client"]._client_id
    if isinstance(adapter, TelemtAdapter):
        state["journal"] = "file" if adapter.journal_path is not None else "memory"
    return state


def _journal(adapter):
    if not isinstance(adapter, TelemtAdapter):
        return None
    if adapter.journal_path is None:
        return {"memory": enc(copy.deepcopy(adapter._journal))}
    try:
        return {"file": adapter.journal_path.read_text()}
    except FileNotFoundError:
        return {"file": None}


def _instrument(cls, methods) -> None:
    original_init = cls.__init__

    @functools.wraps(original_init)
    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        if STATE:
            _wrap_client(self)

    cls.__init__ = init
    for name in methods:
        method = getattr(cls, name)
        signature = inspect.signature(method)

        def make(name, method, signature):
            def arguments(self, args, kwargs):
                bound = signature.bind(self, *args, **kwargs)
                bound.apply_defaults()
                return {key: enc(value) for key, value in list(bound.arguments.items())[1:]}

            def begin(self, args, kwargs):
                _wrap_client(self)
                event = {"adapter": _ident(self, "A"), "state": _state(self), "method": name,
                         "args": arguments(self, args, kwargs), "journal_before": _journal(self)}
                STATE["calls"].append(event)
                return event

            def finish(self, event, outcome, error):
                if error is not None:
                    event["error"] = enc_error(error)
                else:
                    event["result"] = enc(copy.deepcopy(outcome))
                event["journal_after"] = _journal(self)

            if inspect.iscoroutinefunction(method):
                @functools.wraps(method)
                async def wrapper(self, *args, **kwargs):
                    if not STATE or DEPTH.get():
                        return await method(self, *args, **kwargs)
                    event = begin(self, args, kwargs)
                    token = DEPTH.set(1)
                    try:
                        outcome = await method(self, *args, **kwargs)
                    except BaseException as error:
                        finish(self, event, None, error)
                        raise
                    finally:
                        DEPTH.reset(token)
                    finish(self, event, outcome, None)
                    return outcome
            else:
                @functools.wraps(method)
                def wrapper(self, *args, **kwargs):
                    if not STATE or DEPTH.get():
                        return method(self, *args, **kwargs)
                    event = begin(self, args, kwargs)
                    token = DEPTH.set(1)
                    try:
                        outcome = method(self, *args, **kwargs)
                    except BaseException as error:
                        finish(self, event, None, error)
                        raise
                    finally:
                        DEPTH.reset(token)
                    finish(self, event, outcome, None)
                    return outcome
            return wrapper

        setattr(cls, name, make(name, method, signature))


def _instrument_bridge_probe() -> None:
    """`TelemtAdapter.bridge_probe` is an attribute tests replace; record what it is asked."""

    def get(self):
        probe = self.__dict__["_wp6_probe"]

        async def recorded(ingress):
            result = await probe(ingress)
            STATE["probes"].setdefault(_ident(self, "A"), []).append({"ingress": enc(ingress), "result": result})
            return result

        return recorded

    def set_(self, value):
        self.__dict__["_wp6_probe"] = value

    TelemtAdapter.bridge_probe = property(get, set_)


for _cls, _methods in ADAPTERS.items():
    _instrument(_cls, _methods)
_instrument_bridge_probe()
RESULTS: list = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _reset(item.nodeid)
    outcome = yield
    passed = outcome.excinfo is None
    RESULTS.append({"test": item.nodeid, "passed": passed, "calls": STATE["calls"],
                    "clients": STATE["clients"], "probes": STATE["probes"]})
    STATE.clear()


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("TRANSCRIPTS")
    if path:
        Path(path).write_text(json.dumps(RESULTS, indent=1, ensure_ascii=False) + "\n")
