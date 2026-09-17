"""The lanes block of the NaiveProxy Caddyfile (v0.7, docs/spikes/CHAINS_PER_CLIENT.md).

A *lane* is a group of users whose traffic leaves through its own account on the node's
Xray-router ingress — the routing identity of a client, so the router can route their
traffic by their own policy. With `probe_resistance` a `forward_proxy` handler whose
`basic_auth` does not match hands the request to the next handler, so one site may carry
one handler per lane; the service's own handler, the one the manager has always owned,
comes last with everyone else. The manager owns the block:

    route {
        # BEGIN NAIVE-MANAGER LANES
        forward_proxy {
            basic_auth alice <password>
            hide_ip
            hide_via
            probe_resistance
            upstream socks5://grant-7f3a:<key>@127.0.0.1:45101
        }
        # END NAIVE-MANAGER LANES
        forward_proxy {
            # BEGIN NAIVE-MANAGER USERS …

A lane with no enabled user renders no handler, and no lane at all renders no block, so a
node without lanes keeps the Caddyfile it had. What the panel sends is the lane, its users
and the ingress account — never a URL: the ingress endpoint is this host's own
`NAIVE_EGRESS_ROUTER`, and the account is written into the upstream line the way the
service's own router credential is.
"""
from __future__ import annotations

import re

LANES_BEGIN = "# BEGIN NAIVE-MANAGER LANES"
LANES_END = "# END NAIVE-MANAGER LANES"
LANE_ID = re.compile(r"grant:[A-Za-z0-9_-]{1,64}\Z")
ACCOUNT_USER = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
ACCOUNT_PASSWORD = re.compile(r"[A-Za-z0-9._~-]{16,128}\Z")
MAX_LANES = 32
MAX_LANE_USERS = 256
_FORWARD_PROXY = re.compile(r"^\s*forward_proxy(?:\s|$)")
_ROUTE_OPEN = re.compile(r"^\s*route\s*\{\s*(?:#.*)?$")


class LanesInvalid(ValueError):
    """The lanes request is outside the schema this manager renders."""


def lanes_span(lines: list[str]) -> tuple[int, int] | None:
    """Indexes of the marker lines, None without a block, `LanesInvalid` when unpaired."""
    begins = [i for i, line in enumerate(lines) if line.strip() == LANES_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == LANES_END]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise LanesInvalid("managed lanes block must have exactly one marker pair")
    return begins[0], ends[0]


def outside_lanes(lines: list[str]) -> list[int]:
    """Every line index that is not inside the lanes block."""
    span = lanes_span(lines)
    if span is None:
        return list(range(len(lines)))
    return [i for i in range(len(lines)) if not span[0] <= i <= span[1]]


def primary_forward_proxy(lines: list[str]) -> int | None:
    """The index of the service's own `forward_proxy` directive: the one outside the lanes
    block. None when there is none; more than one is the caller's error to name."""
    candidates = [i for i in outside_lanes(lines) if _FORWARD_PROXY.match(lines[i])]
    if len(candidates) != 1:
        return None
    return candidates[0]


def validate_request(body: object, known_users: set[str]) -> list[dict]:
    """`{"lanes": [{"lane", "users": [...], "upstream": {"user", "password"}}]}` — normalised,
    or `LanesInvalid`. Every named user must exist, a user sits in at most one lane."""
    if not isinstance(body, dict) or set(body) != {"lanes"} or not isinstance(body["lanes"], list):
        raise LanesInvalid("invalid lanes request")
    if len(body["lanes"]) > MAX_LANES:
        raise LanesInvalid("too many lanes")
    seen_lanes: set[str] = set()
    seen_users: set[str] = set()
    lanes = []
    for entry in body["lanes"]:
        if not isinstance(entry, dict) or set(entry) != {"lane", "users", "upstream"}:
            raise LanesInvalid("invalid lane")
        lane = entry["lane"]
        if not isinstance(lane, str) or LANE_ID.fullmatch(lane) is None or lane in seen_lanes:
            raise LanesInvalid("invalid lane id")
        users = entry["users"]
        if not isinstance(users, list) or not users or len(users) > MAX_LANE_USERS:
            raise LanesInvalid("a lane names its users")
        for user in users:
            if not isinstance(user, str) or user not in known_users:
                raise LanesInvalid("unknown lane user")
            if user in seen_users:
                raise LanesInvalid("a user sits in one lane")
            seen_users.add(user)
        upstream = entry["upstream"]
        if (not isinstance(upstream, dict) or set(upstream) != {"user", "password"}
                or not isinstance(upstream["user"], str) or ACCOUNT_USER.fullmatch(upstream["user"]) is None
                or not isinstance(upstream["password"], str) or ACCOUNT_PASSWORD.fullmatch(upstream["password"]) is None):
            raise LanesInvalid("invalid lane upstream account")
        seen_lanes.add(lane)
        lanes.append({"lane": lane, "users": list(users), "upstream": {"user": upstream["user"], "password": upstream["password"]}})
    return lanes


def handler_lines(users: list[tuple[str, str]], upstream_url: str, indent: str) -> list[str]:
    """One lane's `forward_proxy` handler: its enabled users, the fixed options of the
    service's own handler, and the lane's upstream."""
    inner = indent + "    "
    lines = [f"{indent}forward_proxy {{"]
    lines += [f"{inner}basic_auth {username} {password}" for username, password in users]
    lines += [f"{inner}hide_ip", f"{inner}hide_via", f"{inner}probe_resistance", f"{inner}upstream {upstream_url}", f"{indent}}}"]
    return lines


def render(text: str, lanes: list[tuple[list[tuple[str, str]], str]]) -> str:
    """The Caddyfile with the lanes block carrying `lanes` — `(enabled users, upstream URL)`
    per lane, in order, lanes without users skipped — inserted at the top of `route { }` or
    replacing the block that is there; no lanes, no block."""
    lines = text.splitlines()
    span = lanes_span(lines)
    if span is not None:
        indent = re.match(r"^(\s*)", lines[span[0]]).group(1)
        del lines[span[0]:span[1] + 1]
        position = span[0]
    else:
        routes = [i for i, line in enumerate(lines) if _ROUTE_OPEN.match(line)]
        if len(routes) != 1:
            raise LanesInvalid("exactly one route block is required")
        position = routes[0] + 1
        indent = re.match(r"^(\s*)", lines[routes[0]]).group(1) + "    "
    block: list[str] = []
    for users, upstream_url in lanes:
        if users:
            block += handler_lines(users, upstream_url, indent)
    if block:
        block = [f"{indent}{LANES_BEGIN}", *block, f"{indent}{LANES_END}"]
    lines[position:position] = block
    return "\n".join(lines) + "\n"


def lane_credentials(text: str) -> list[list[tuple[str, str]]]:
    """The `basic_auth` pairs of every handler inside the lanes block, handler by handler —
    what the consistency check compares with the state."""
    lines = text.splitlines()
    span = lanes_span(lines)
    if span is None:
        return []
    handlers: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] | None = None
    for line in lines[span[0] + 1:span[1]]:
        if _FORWARD_PROXY.match(line):
            current = []
            handlers.append(current)
        elif match := re.match(r"^\s*basic_auth\s+(\S+)\s+(\S+)\s*$", line):
            if current is None:
                raise LanesInvalid("basic_auth outside a lane handler")
            current.append((match.group(1), match.group(2)))
    return handlers
