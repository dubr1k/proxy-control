"""Test-only launcher for an explicitly verified external Python 3.3 source tree.

Invoked by mixed_delivery.py with the historical tree as its sole PYTHONPATH.
No legacy application implementation is vendored into the native release.
"""
from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--socket", required=True)
    args = parser.parse_args()

    import panel
    import uvicorn
    from panel.app import create_app

    assert Path(panel.__file__).resolve().parent == args.source.resolve() / "panel"
    app = create_app()

    @asynccontextmanager
    async def controlled_lifespan(_app):
        # Deterministic external fixture scheduling; application methods are unmodified.
        await app.state.access_enforcer.tick(force=True)
        yield

    app.router.lifespan_context = controlled_lifespan

    @app.post("/__test/tick/pusher")
    async def tick_pusher():
        await app.state.pusher.tick()
        return {"ok": True}

    @app.post("/__test/settle")
    async def settle():
        await app.state.reconciler.run_pending()
        return {"ok": True}

    uvicorn.run(app, uds=args.socket, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
