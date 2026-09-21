"""Tools from the panel's OpenAPI schema (spec §9a): one per operation, named
`<method>_<path>` (`/api/` dropped, `{x}` → `by_x`), the input schema merged from path
parameters, query parameters and the request body; irreversible operations carry a
required `confirm` and refuse without it — before the panel is ever called."""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

from mcp_types import CallToolResult, Resource, TextContent, Tool

from .panel import PanelClient, PanelError, encode_path

METHODS = ("get", "post", "put", "patch", "delete")
BODY_METHODS = {"POST", "PUT", "PATCH"}
NAME_LIMIT = 64
# Paths the MCP server does not expose: its own schema and health, the login surface,
# the one-shot reveal (consumed by the curated tools), the subscriber endpoint and the
# node API behind a fleet key. Anything outside `/api/` is the browser's, not the API's.
EXCLUDED_EXACT = {"/api/openapi.json", "/healthz", "/login", "/api/reveal/{token}"}
EXCLUDED_PREFIXES = ("/api/auth/", "/s/", "/api/fleet/")
# Mutations that cannot be undone: a `DELETE`, or a POST/PUT on one of these paths.
IRREVERSIBLE_MARKERS = ("/update", "/rollback", "/unlink", "/revoke", "/rotate", "/delete", "/archive",
                        "/check", "/exits/test", "/reset-quota", "/reset-metrics",
                        # `POST /api/nodes/{node_id}/versions/{component}` installs a version on a node.
                        "/versions/{component}")
CONFIRM_SCHEMA = {
    "type": "boolean",
    "description": "This operation cannot be undone. Pass true to run it; without it the tool only "
                   "describes what it would do.",
}


def tool_name(method: str, path: str) -> str:
    stem = path[len("/api/"):] if path.startswith("/api/") else path.lstrip("/")
    stem = re.sub(r"\{([^}]+)\}", r"by_\1", stem)
    name = f"{method.lower()}_{stem}".replace("/", "_")
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", name).strip("_")
    return name[:NAME_LIMIT].rstrip("_")


def is_excluded(path: str) -> bool:
    return (not path.startswith("/api/")) or path in EXCLUDED_EXACT or path.startswith(EXCLUDED_PREFIXES)


def is_irreversible(method: str, path: str) -> bool:
    method = method.upper()
    if method == "DELETE":
        return True
    return method in ("POST", "PUT") and any(marker in path for marker in IRREVERSIBLE_MARKERS)


def resolve_refs(schema: Any, components: dict[str, Any], depth: int = 0) -> Any:
    """The schema with every `$ref` into `components/schemas` inlined (bounded depth, so
    a recursive model cannot spin the builder)."""
    if not isinstance(schema, (dict, list)):
        return schema
    if isinstance(schema, list):
        return [resolve_refs(item, components, depth) for item in schema]
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        target = components.get(name)
        if target is None or depth >= 8:
            return {"type": "object"}
        # `depth` counts reference hops, not nesting: a deep model is fine, a cycle is cut.
        return {**resolve_refs(target, components, depth + 1), **{k: v for k, v in schema.items() if k != "$ref"}}
    return {key: resolve_refs(value, components, depth) for key, value in schema.items()}


def _body_schema(operation: dict[str, Any], components: dict[str, Any]) -> dict[str, Any] | None:
    content = operation.get("requestBody", {}).get("content", {})
    schema = content.get("application/json", {}).get("schema")
    if schema is None:
        return None
    schema = resolve_refs(schema, components)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            objects = [item for item in schema[key] if isinstance(item, dict) and item.get("type") != "null"]
            schema = objects[0] if objects else {}
            break
    if "allOf" in schema:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for item in schema["allOf"]:
            merged["properties"].update(item.get("properties", {}))
            merged["required"] += item.get("required", [])
        schema = merged
    return schema


@dataclass
class Operation:
    name: str
    method: str
    path: str
    description: str
    input_schema: dict[str, Any]
    path_params: list[str]
    query_params: list[str]
    body_keys: list[str]
    body_is_raw: bool = False
    confirm: str = "none"  # none | required | optional
    required_body: bool = False
    param_enums: dict[str, list[str]] = field(default_factory=dict)

    def tool(self) -> Tool:
        return Tool(name=self.name, description=self.description, input_schema=self.input_schema)

    def needs_confirm(self, concrete_path: str) -> bool:
        return self.confirm == "required" or (self.confirm == "optional" and is_irreversible(self.method, concrete_path))


def build_operations(schema: dict[str, Any]) -> list[Operation]:
    components = schema.get("components", {}).get("schemas", {})
    operations: list[Operation] = []
    seen: set[str] = set()
    for path, methods in sorted(schema.get("paths", {}).items()):
        if is_excluded(path):
            continue
        for method in METHODS:
            operation = methods.get(method)
            if operation is None:
                continue
            name = tool_name(method, path)
            if name in seen:
                continue  # two operations collapsing to one name: the first wins
            seen.add(name)
            operations.append(_build(name, method.upper(), path, operation, components))
    return operations


def _build(name: str, method: str, path: str, operation: dict[str, Any], components: dict[str, Any]) -> Operation:
    properties: dict[str, Any] = {}
    required: list[str] = []
    path_params: list[str] = []
    query_params: list[str] = []
    param_enums: dict[str, list[str]] = {}
    for parameter in operation.get("parameters", []):
        parameter = resolve_refs(parameter, components)
        location, pname = parameter.get("in"), parameter.get("name")
        if location not in ("path", "query") or not pname:
            continue
        pschema = copy.deepcopy(parameter.get("schema", {"type": "string"}))
        if parameter.get("description") and "description" not in pschema:
            pschema["description"] = parameter["description"]
        properties[pname] = pschema
        (path_params if location == "path" else query_params).append(pname)
        if location == "path" or parameter.get("required"):
            required.append(pname)
        enum = pschema.get("enum") or next((item.get("enum") for item in pschema.get("anyOf", []) if item.get("enum")), None)
        if location == "path" and enum:
            param_enums[pname] = list(enum)
    body = _body_schema(operation, components)
    body_keys: list[str] = []
    body_is_raw = False
    if body is not None:
        if body.get("type") == "object" or "properties" in body:
            for key, value in body.get("properties", {}).items():
                if key in properties:
                    continue  # a path/query parameter of the same name wins
                properties[key] = value
                body_keys.append(key)
            required += [key for key in body.get("required", []) if key in body_keys]
        else:
            properties["body"] = {**body, "description": body.get("description", "The request body.")}
            body_keys, body_is_raw = ["body"], True
            if operation.get("requestBody", {}).get("required"):
                required.append("body")
    confirm = "none"
    if is_irreversible(method, path):
        confirm = "required"
    elif method in ("POST", "PUT") and any(
        is_irreversible(method, path.replace("{" + pname + "}", value))
        for pname, values in param_enums.items() for value in values
    ):
        confirm = "optional"
    if confirm != "none":
        properties["confirm"] = dict(CONFIRM_SCHEMA)
        if confirm == "required":
            required.append("confirm")
    input_schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        input_schema["required"] = required
    parts = [operation.get("summary", "").strip(), operation.get("description", "").strip()]
    description = "\n\n".join(part for part in parts if part)
    description = f"{description}\n\n{method} {path}" if description else f"{method} {path}"
    if confirm == "required":
        description += "\n\nIrreversible: requires confirm=true."
    return Operation(name=name, method=method, path=path, description=description, input_schema=input_schema,
                     path_params=path_params, query_params=query_params, body_keys=body_keys, body_is_raw=body_is_raw,
                     confirm=confirm, required_body=bool(operation.get("requestBody", {}).get("required")),
                     param_enums=param_enums)


def text_result(value: Any, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(value, ensure_ascii=False, indent=1, default=str))],
                          is_error=is_error)


def refusal(method: str, path: str, detail: str | None = None, **extra: Any) -> CallToolResult:
    return text_result({
        "refused": True,
        "would": f"{method} {path}",
        "detail": detail or "This operation cannot be undone. Call again with confirm=true to run it.",
        **extra,
    })


async def run_operation(panel: PanelClient, operation: Operation, arguments: dict[str, Any]) -> CallToolResult:
    arguments = dict(arguments or {})
    confirmed = arguments.pop("confirm", None) is True
    missing = [name for name in operation.path_params if name not in arguments]
    if missing:
        return text_result({"error": f"missing path parameter(s): {', '.join(missing)}"}, is_error=True)
    path = encode_path(operation.path, {name: arguments.pop(name) for name in operation.path_params})
    if operation.needs_confirm(path) and not confirmed:
        return refusal(operation.method, path)
    query = {name: arguments.pop(name) for name in operation.query_params if name in arguments}
    body: Any = None
    if operation.method in BODY_METHODS:
        body = arguments.pop("body", None) if operation.body_is_raw else {k: v for k, v in arguments.items() if k in operation.body_keys}
        if body == {} and not operation.required_body and not operation.body_keys:
            body = None
    else:
        query.update({k: v for k, v in arguments.items() if v is not None})
    try:
        answer = await panel.request(operation.method, path, params=query, json=body)
    except PanelError as exc:
        return text_result(exc.payload(), is_error=True)
    return text_result(answer if answer is not None else {"ok": True, "status": "no content"})


class ToolRegistry:
    """Everything `tools/list`, `tools/call`, `resources/list` and `resources/read` answer:
    the generated operations (rebuilt by `reload`), the curated tools and the resources."""

    def __init__(self, panel: PanelClient):
        from .curated import CURATED, RESOURCES  # noqa: PLC0415 — the curated module imports this one

        self.panel = panel
        self.operations: dict[str, Operation] = {}
        self.curated = {tool.name: tool for tool in CURATED}
        self._resources = RESOURCES
        self.schema_loaded = False

    async def reload(self) -> int:
        schema = await self.panel.get("/api/openapi.json")
        if not isinstance(schema, dict) or "paths" not in schema:
            raise PanelError(502, "the panel did not return an OpenAPI document", "bad_schema")
        self.operations = {op.name: op for op in build_operations(schema) if op.name not in self.curated}
        self.schema_loaded = True
        return len(self.operations)

    def tools(self) -> list[Tool]:
        return [tool.tool() for tool in self.curated.values()] + [op.tool() for op in self.operations.values()]

    async def call(self, name: str, arguments: dict[str, Any] | None) -> CallToolResult:
        arguments = dict(arguments or {})
        if name == "reload_tools":
            try:
                await self.reload()
            except PanelError as exc:
                return text_result(exc.payload(), is_error=True)
            return text_result({"reloaded": True, "tools": len(self.tools())})
        curated = self.curated.get(name)
        if curated is not None:
            try:
                return await curated.handler(self.panel, arguments)
            except PanelError as exc:
                return text_result(exc.payload(), is_error=True)
        operation = self.operations.get(name)
        if operation is None:
            return text_result({"error": f"unknown tool {name!r}"}, is_error=True)
        return await run_operation(self.panel, operation, arguments)

    def resources(self) -> list[Resource]:
        return [Resource(uri=uri, name=uri.split("//", 1)[1], description=description, mime_type="application/json")
                for uri, (description, _reader) in self._resources.items()]

    async def read_resource(self, uri: str) -> str:
        entry = self._resources.get(uri)
        if entry is None:
            raise PanelError(404, f"unknown resource {uri}", "unknown_resource")
        return json.dumps(await entry[1](self.panel), ensure_ascii=False, indent=1, default=str)
