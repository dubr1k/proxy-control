"""The curated tools (spec §9a): the operator's everyday moves in one call each, with
hand-written descriptions — a client with its placement and its subscription link, a
version check and update, a routing preview and apply, the audit tail — and the three
resources. Every mutation that cannot be undone asks for `confirm`."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from mcp_types import CallToolResult, Tool

from .panel import PanelClient, PanelError, encode_path
from .tools import CONFIRM_SCHEMA, refusal, text_result

Handler = Callable[[PanelClient, dict[str, Any]], Awaitable[CallToolResult]]

PLACEMENT_ITEM = {
    "type": "object",
    "properties": {
        "node_id": {"type": "string", "description": "The node: `local` for this panel, or a linked panel's id."},
        "protocol": {"type": "string", "enum": ["mtproxy", "naive", "mieru"]},
        "runtime_username": {"type": "string", "description": "Account name on the runtime; derived from the display name when omitted."},
        "options": {"type": "object", "description": "Protocol options (quota, limits…); the panel validates them."},
    },
    "required": ["node_id", "protocol"],
    "additionalProperties": False,
}
PLACEMENT = {"type": "array", "items": PLACEMENT_ITEM, "description": "The node×protocol matrix the client should have."}


@dataclass(frozen=True)
class CuratedTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler

    def tool(self) -> Tool:
        return Tool(name=self.name, description=self.description, input_schema=self.input_schema)


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def derive_username(display_name: str) -> str:
    """`Alice Example` → `alice-example`: what the panel's dialog proposes, within the
    runtime username rule `[A-Za-z0-9_.-]{1,64}`."""
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", display_name.strip().lower()).strip("-.")
    return (value or "client")[:64]


def _strip_qr(payload: dict[str, Any]) -> dict[str, Any]:
    """The reveal payload without its QR images: a model reads the link, not a picture."""
    return {
        "subscription_id": payload.get("subscription_id"),
        "generation": payload.get("generation"),
        "url": payload.get("url"),
        "variants": {name: item.get("url") for name, item in (payload.get("variants") or {}).items() if isinstance(item, dict)},
    }


async def _reveal(panel: PanelClient, token: str) -> dict[str, Any]:
    return _strip_qr(await panel.get(encode_path("/api/reveal/{token}", {"token": token})))


# --- overview --------------------------------------------------------------------------


async def overview_data(panel: PanelClient) -> dict[str, Any]:
    nodes = await panel.get("/api/nodes")
    return {
        "dashboard": await panel.get("/api/dashboard"),
        "versions": await panel.get("/api/versions"),
        "nodes": nodes.get("items", nodes) if isinstance(nodes, dict) else nodes,
    }


async def overview(panel: PanelClient, _arguments: dict[str, Any]) -> CallToolResult:
    return text_result(await overview_data(panel))


async def versions_data(panel: PanelClient) -> Any:
    return await panel.get("/api/versions")


async def nodes_data(panel: PanelClient) -> Any:
    nodes = await panel.get("/api/nodes")
    return nodes.get("items", nodes) if isinstance(nodes, dict) else nodes


# --- clients ---------------------------------------------------------------------------


def _grants_body(placement: list[dict[str, Any]], username: str) -> dict[str, Any]:
    return {"grants": [
        {"protocol": item["protocol"], "node_id": item.get("node_id", "local"),
         "runtime_username": item.get("runtime_username") or username, "options": item.get("options") or {}}
        for item in placement
    ]}


async def create_client(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    display_name = str(arguments.get("display_name", "")).strip()
    if not display_name:
        return text_result({"error": "display_name is required"}, is_error=True)
    placement = list(arguments.get("placement") or [])
    subscription = arguments.get("subscription", True) is not False
    client = await panel.post("/api/clients", {"display_name": display_name, "subscription": subscription})
    result: dict[str, Any] = {"client": {k: v for k, v in client.items() if k != "subscription_reveal_token"},
                              "grants": None, "subscription_url": None, "subscription": None}
    if placement:
        result["grants"] = await panel.post(encode_path("/api/clients/{client_id}/grants", {"client_id": client["id"]}),
                                            _grants_body(placement, derive_username(display_name)))
    if client.get("subscription_reveal_token"):
        revealed = await _reveal(panel, client["subscription_reveal_token"])
        result["subscription"] = revealed
        result["subscription_url"] = revealed["url"]
    elif subscription:
        result["subscription"] = {"note": "no subscription domain is configured on this panel"}
    return text_result(result)


async def client_subscription(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    client_id = str(arguments.get("client_id", ""))
    answer = await panel.post(encode_path("/api/clients/{client_id}/subscription/reveal", {"client_id": client_id}))
    return text_result(await _reveal(panel, answer["reveal_token"]))


async def set_client_placement(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    client_id = str(arguments.get("client_id", ""))
    desired = [(item["node_id"], item["protocol"]) for item in arguments.get("placement") or []]
    current = await panel.get(encode_path("/api/clients/{client_id}", {"client_id": client_id}))
    grants = [g for g in current.get("grants", []) if g.get("desired_state") != "deleted"]
    by_key = {(g["node_id"], g["protocol"]): g for g in grants}
    plan: dict[str, list[dict[str, Any]]] = {"issue": [], "enable": [], "disable": [], "keep": []}
    for key in desired:
        grant = by_key.get(key)
        if grant is None:
            plan["issue"].append({"node_id": key[0], "protocol": key[1]})
        elif grant.get("desired_state") == "enabled":
            plan["keep"].append({"grant_id": grant["id"], "node_id": key[0], "protocol": key[1]})
        else:
            plan["enable"].append({"grant_id": grant["id"], "node_id": key[0], "protocol": key[1]})
    for key, grant in by_key.items():
        if key not in desired and grant.get("desired_state") == "enabled":
            plan["disable"].append({"grant_id": grant["id"], "node_id": key[0], "protocol": key[1]})
    if arguments.get("confirm") is not True:
        return refusal("PLAN", f"/api/clients/{client_id}", "Placement change planned; call again with confirm=true to run it.",
                       plan=plan)
    username = next((g.get("runtime_username") for g in grants if g.get("runtime_username")), None) \
        or derive_username(str(current.get("client", {}).get("display_name") or client_id))
    results: dict[str, Any] = {"issued": None, "enabled": [], "disabled": []}
    for step in plan["disable"]:
        await panel.post(encode_path("/api/clients/grants/{grant_id}/disable", {"grant_id": step["grant_id"]}))
        results["disabled"].append(step["grant_id"])
    for step in plan["enable"]:
        await panel.post(encode_path("/api/clients/grants/{grant_id}/enable", {"grant_id": step["grant_id"]}))
        results["enabled"].append(step["grant_id"])
    if plan["issue"]:
        wanted = {(item["node_id"], item["protocol"]): item for item in arguments.get("placement") or []}
        results["issued"] = await panel.post(encode_path("/api/clients/{client_id}/grants", {"client_id": client_id}),
                                             _grants_body([wanted[(s["node_id"], s["protocol"])] for s in plan["issue"]], username))
    return text_result({"refused": False, "plan": plan, "results": results})


# --- versions, routing, audit ----------------------------------------------------------


async def versions_check(panel: PanelClient, _arguments: dict[str, Any]) -> CallToolResult:
    return text_result(await panel.post("/api/versions/check"))


async def versions_update(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    path = encode_path("/api/versions/{component}/update", {"component": arguments.get("component", "")})
    if arguments.get("confirm") is not True:
        return refusal("POST", path, f"Would install {arguments.get('component')} {arguments.get('version')} "
                                     f"(expecting {arguments.get('expected_current')} now). Call again with confirm=true.")
    body = {"version": arguments.get("version"), "expected_current": arguments.get("expected_current")}
    return text_result(await panel.post(path, body))


async def routing_preview(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    path = encode_path("/api/routing/policies/{node_id}/{protocol}/preview",
                       {"node_id": arguments.get("node_id", ""), "protocol": arguments.get("protocol", "")})
    return text_result(await panel.post(path, arguments.get("policy"), lane=arguments.get("lane") or "svc"))


async def routing_apply(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    path = encode_path("/api/routing/policies/{node_id}/{protocol}/apply",
                       {"node_id": arguments.get("node_id", ""), "protocol": arguments.get("protocol", "")})
    lane = arguments.get("lane") or "svc"
    if arguments.get("confirm") is not True:
        return refusal("POST", f"{path}?lane={lane}", "Would apply the saved policy to the node's backend. "
                                                      "Call again with confirm=true.")
    return text_result(await panel.post(path, {"expected_revision": arguments.get("expected_revision")}, lane=lane))


async def audit_tail(panel: PanelClient, arguments: dict[str, Any]) -> CallToolResult:
    params = {key: arguments.get(key) for key in ("actor", "action", "target", "request_id", "before_id")}
    return text_result(await panel.get("/api/audit", limit=int(arguments.get("limit") or 50), **params))


async def reload_tools(_panel: PanelClient, _arguments: dict[str, Any]) -> CallToolResult:  # pragma: no cover
    raise PanelError(500, "reload_tools is handled by the registry", "internal")


CURATED: tuple[CuratedTool, ...] = (
    CuratedTool(
        "overview",
        "One picture of the panel: the dashboard (runtimes, clients, server resources), the installed and available "
        "component versions and the nodes with their status. GET /api/dashboard + /api/versions + /api/nodes.",
        _schema({}), overview,
    ),
    CuratedTool(
        "create_client",
        "Create a client, place it on nodes and protocols, and return its subscription URL in one go: "
        "POST /api/clients, then POST /api/clients/{id}/grants with the placement, then the one-shot reveal. "
        "`placement` is a list of {node_id, protocol}; the account name defaults to the display name in lower case.",
        _schema({
            "display_name": {"type": "string", "minLength": 1, "maxLength": 128},
            "placement": PLACEMENT,
            "subscription": {"type": "boolean", "default": True, "description": "Issue a subscription URL (needs the panel's subscription domain)."},
        }, ["display_name"]),
        create_client,
    ),
    CuratedTool(
        "client_subscription",
        "Show a client's subscription URL again (and its client-format variants). The panel opens the escrowed "
        "token for one reveal and records it in the audit log.",
        _schema({"client_id": {"type": "string"}}, ["client_id"]),
        client_subscription,
    ),
    CuratedTool(
        "set_client_placement",
        "Bring a client's node×protocol matrix to the desired one: issue the missing grants, enable the disabled "
        "ones that are wanted, disable the enabled ones that are not (nothing is deleted). Without confirm the tool "
        "only reports the plan; with confirm=true it runs it.",
        _schema({"client_id": {"type": "string"}, "placement": PLACEMENT, "confirm": dict(CONFIRM_SCHEMA)},
                ["client_id", "placement"]),
        set_client_placement,
    ),
    CuratedTool(
        "versions_check",
        "Ask the version-agent to poll upstream (GitHub Releases, image registries) for newer component versions. "
        "POST /api/versions/check; the result lands in `overview`/`proxy-control://versions`.",
        _schema({}), versions_check,
    ),
    CuratedTool(
        "versions_update",
        "Install a component version through the version-agent, with rollback on failure. "
        "POST /api/versions/{component}/update; `expected_current` must match the installed version. Irreversible: "
        "requires confirm=true.",
        _schema({
            "component": {"type": "string", "enum": ["telemt", "naive", "mita", "xray", "panel"]},
            "version": {"type": "string"},
            "expected_current": {"type": "string"},
            "confirm": dict(CONFIRM_SCHEMA),
        }, ["component", "version", "expected_current", "confirm"]),
        versions_update,
    ),
    CuratedTool(
        "routing_preview",
        "Preview what a node's backend would enforce for a routing policy without saving or applying anything. "
        "POST /api/routing/policies/{node_id}/{protocol}/preview; `policy` is the policy body (omit it to preview "
        "the saved one); `lane` is `svc` (default) or `grant:<grant_id>`.",
        _schema({
            "node_id": {"type": "string"}, "protocol": {"type": "string", "enum": ["naive", "mieru", "mtproxy"]},
            "policy": {"type": ["object", "null"], "description": "The policy to preview; null = the saved policy."},
            "lane": {"type": "string", "default": "svc"},
        }, ["node_id", "protocol"]),
        routing_preview,
    ),
    CuratedTool(
        "routing_apply",
        "Apply the saved routing policy revision to the node's backend (transactional, with rollback). "
        "POST /api/routing/policies/{node_id}/{protocol}/apply with `expected_revision`. Requires confirm=true.",
        _schema({
            "node_id": {"type": "string"}, "protocol": {"type": "string", "enum": ["naive", "mieru", "mtproxy"]},
            "expected_revision": {"type": "integer", "minimum": 1},
            "lane": {"type": "string", "default": "svc"},
            "confirm": dict(CONFIRM_SCHEMA),
        }, ["node_id", "protocol", "expected_revision", "confirm"]),
        routing_apply,
    ),
    CuratedTool(
        "audit_tail",
        "The newest audit rows (who did what, from where, under which request id). GET /api/audit; "
        "MCP actions appear with `via: api-key` and the key's name.",
        _schema({
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            "actor": {"type": "string"}, "action": {"type": "string"}, "target": {"type": "string"},
            "request_id": {"type": "string"}, "before_id": {"type": "integer", "minimum": 1},
        }),
        audit_tail,
    ),
    CuratedTool(
        "reload_tools",
        "Fetch the panel's OpenAPI schema again and rebuild the generated tools (after a panel update).",
        _schema({}), reload_tools,
    ),
)

RESOURCES: dict[str, tuple[str, Callable[[PanelClient], Awaitable[Any]]]] = {
    "proxy-control://overview": ("Dashboard, versions and nodes in one JSON document.", overview_data),
    "proxy-control://versions": ("Installed and available component versions (GET /api/versions).", versions_data),
    "proxy-control://nodes": ("This panel's nodes with their status (GET /api/nodes).", nodes_data),
}
