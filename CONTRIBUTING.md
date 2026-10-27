# Contributing to Proxy Control

## Before opening an issue

Search existing reports and remove credentials, access links, QR codes, certificates, public IPs, production hostnames and unsanitized logs. Security vulnerabilities belong in the private reporting path described in [SECURITY.md](SECURITY.md).

## Development

Use the pinned Rust 1.99 toolchain and Python 3.12 on Ubuntu 24.04 for
development and external black-box tests. Production hosts do not run Python:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
cargo test --manifest-path panel/Cargo.toml --workspace --locked
cargo test --manifest-path version_agent/Cargo.toml --locked
cargo test --manifest-path installer/Cargo.toml --locked
cargo build --manifest-path panel/Cargo.toml --locked -p panel-web --features test-hooks
cargo build --manifest-path installer/Cargo.toml --locked --bin proxy-control-installer
install -D -m 0755 installer/target/debug/proxy-control-installer installer/bin/linux-amd64/proxy-control-installer
docker build -f panel/Dockerfile -t mtproxy-panel:latest .
docker build -f mieru_manager/Dockerfile -t mtproxy-mieru-manager:latest .
PANEL_IMPL=rust PANEL_RUST_BIN="$PWD/panel/target/debug/panel" PANEL_TEST_IMAGE=mtproxy-panel:latest \
  sudo --preserve-env=PANEL_IMPL,PANEL_RUST_BIN,PANEL_TEST_IMAGE .venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
```

Render every affected Compose combination and build affected images. The exact CI model and environment placeholders are in `.github/workflows/test.yml`.

## Architecture rules

- Preserve active runtime paths, Compose names/volumes and commands documented in [COMPATIBILITY.md](docs/COMPATIBILITY.md); discover and protect historical Fleet v1 units/URI identifiers during explicit migration, but do not reinstall them in the native release.
- Keep protocol-specific MTProxy keys and names where they describe MTProto.
- Keep Mieru/mita as an external GPLv3+ process; do not copy GPL source/generated stubs into the MIT adapter.
- Do not widen manager APIs, mount a Docker socket, expose management ports, weaken fail-closed transactions, or invent accounting precision.
- Require explicit production hostnames and secret input; examples use RFC domains.

## Pull requests

Create a focused branch, add regression tests before/following the fix, update both README languages when their shared structure changes, and complete the PR checklist. Explain security boundaries, compatibility impact, rollback, accounting impact, and validation evidence. Keep generated/private files out of Git and ensure `git diff --check` is clean.

Contributions are accepted under the repository MIT license unless explicitly agreed otherwise. Third-party material must include verified provenance and compatible notices; do not change `LICENSE` copyright text as a drive-by edit.
