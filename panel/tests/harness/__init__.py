"""Conformance harness of the panel test suite (Rust port, WP0).

- `fake_managers`: every in-memory manager double re-hosted behind a real server that speaks the
  manager's wire protocol (Unix sockets; TCP for Telemt). The panel reaches them through its real
  clients, so the same tests hold a Python panel and a Rust panel to one wire contract.
- `server`: `PanelServer` — one panel under test, `PANEL_IMPL=python` (in-process app) or
  `PANEL_IMPL=rust` (the binary from `PANEL_RUST_BIN` on a Unix socket), with the clock/tick/
  probe-bridge hooks and CLI seeding.
- `markers`: the automatic `blackbox` / `internal` / `unit` / `static` / `browser` / `fleet_v1`
  classification and what `PANEL_IMPL=rust` deselects.
"""
