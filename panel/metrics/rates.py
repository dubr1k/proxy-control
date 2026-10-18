"""Counter arithmetic: reset-safe deltas and per-client rates."""
from __future__ import annotations

from dataclasses import dataclass


def fold(previous: float | None, reading: float) -> float | None:
    """The growth since `previous`. First sight is a baseline (None, no spike); a lower
    reading is a counter reset, so the growth is the reading itself."""
    if previous is None:
        return None
    return reading - previous if reading >= previous else reading


def _number(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


@dataclass
class ClientRate:
    up_bps: float | None
    down_bps: float | None
    total_bps: float
    up_delta: float
    down_delta: float
    total_delta: float
    seen: float


class ClientRates:
    """Per-client rates from cumulative counters, keyed by (protocol, username).

    Time is monotonic seconds supplied by the caller. A client unseen for `forget_after`
    seconds is dropped, so memory follows the live client list."""

    def __init__(self, forget_after: float = 600.0):
        self.forget_after = forget_after
        self._last: dict[tuple[str, str], tuple[float | None, float | None, float | None, float]] = {}
        self._rate: dict[tuple[str, str], ClientRate] = {}

    def update(self, protocol: str, username: str, now: float, *, up=None, down=None, total=None) -> ClientRate | None:
        """Feed one reading. `up`/`down` are directional counters, `total` a combined one
        (Telemt). Returns the new rate, or None for the baseline reading."""
        key = (protocol, username)
        up, down, total = _number(up), _number(down), _number(total)
        if total is None and up is not None and down is not None:
            total = up + down
        previous = self._last.get(key)
        self._last[key] = (up, down, total, now)
        if previous is None:
            return None
        p_up, p_down, p_total, then = previous
        dt = now - then
        if dt <= 0:
            return self._rate.get(key)
        d_up = fold(p_up, up) if up is not None else None
        d_down = fold(p_down, down) if down is not None else None
        d_total = fold(p_total, total) if total is not None else None
        if d_total is None:
            return self._rate.get(key)
        if d_up is not None and d_down is not None:
            d_total = d_up + d_down
        rate = ClientRate(
            up_bps=None if d_up is None else d_up / dt,
            down_bps=None if d_down is None else d_down / dt,
            total_bps=d_total / dt, up_delta=d_up or 0.0, down_delta=d_down or 0.0,
            total_delta=d_total, seen=now,
        )
        self._rate[key] = rate
        return rate

    def current(self, protocol: str, now: float, max_age: float) -> dict[str, ClientRate]:
        """The rates of a protocol's clients refreshed within `max_age` seconds."""
        return {user: rate for (proto, user), rate in self._rate.items()
                if proto == protocol and now - rate.seen <= max_age}

    def prune(self, now: float) -> None:
        for key in [k for k, value in self._last.items() if now - value[3] > self.forget_after]:
            self._last.pop(key, None)
            self._rate.pop(key, None)

    def __len__(self) -> int:
        return len(self._last)
