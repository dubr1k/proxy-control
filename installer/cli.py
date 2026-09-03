from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TextIO

from installer.config import ConfigError, load_config
from installer.i18n import Locale, parse_locale, text
from installer.model import InstallerConfig
from installer.planner import AuditFacts, InstallPlan, PlanError
from installer.transaction import (
    OwnershipError,
    TransactionEngine,
    TransactionError,
    TransactionState,
    TransactionStore,
    import_runtime_v2,
)
from installer.wizard import (
    TerminalIO,
    TerminalWizard,
    WizardIO,
    WizardQuit,
    WizardSaved,
)


_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_12 = re.compile(r"[0-9a-f]{12}\Z")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|private[_ -]?key|api[_ -]?key)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
_LEGACY_STATE = Path("var/lib/proxy-control/runtime.json")


class CliError(RuntimeError):
    """A requested lifecycle operation cannot safely proceed."""


class WizardRunner(Protocol):
    def run(self, facts: AuditFacts) -> InstallerConfig: ...


@dataclass(frozen=True)
class CliServices:
    """Composition boundary shared by interactive and automated entry points."""

    audit: Callable[[InstallerConfig | None], AuditFacts]
    plan: Callable[[InstallerConfig, AuditFacts], InstallPlan]
    engine: TransactionEngine
    store: TransactionStore
    wizard: Callable[[WizardIO, Locale | None, Path], WizardRunner]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy-control-installer",
        description="Typed Proxy Control release installer",
    )
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    subcommands = parser.add_subparsers(dest="command", required=True)

    wizard = subcommands.add_parser("wizard", help="start the interactive installer")
    wizard.add_argument("--lang", choices=tuple(Locale))
    wizard.add_argument("--config-output", type=Path, default=Path("proxy-control.toml"))
    wizard.add_argument("--json", action="store_true")

    plan = subcommands.add_parser("plan", help="render a deterministic mutation plan")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--json", action="store_true")

    install = subcommands.add_parser("install", help="apply an accepted deterministic plan")
    install.add_argument("--config", type=Path, required=True)
    install.add_argument("--accept-plan", required=True)
    install.add_argument("--json", action="store_true")

    status = subcommands.add_parser("status", help="show sanitized transaction status")
    status.add_argument("--json", action="store_true")

    for name in ("resume", "repair"):
        command = subcommands.add_parser(name, help=f"{name} the owned transaction")
        command.add_argument("--json", action="store_true")

    uninstall = subcommands.add_parser("uninstall", help="remove the owned transaction")
    uninstall.add_argument("--purge-data", action="store_true")
    uninstall.add_argument("--json", action="store_true")
    return parser


def _default_services(root: Path) -> CliServices:
    store = TransactionStore(root)
    engine = TransactionEngine(store, {})

    def unavailable_plan(_config: InstallerConfig, _facts: AuditFacts) -> InstallPlan:
        raise CliError("profile adapters and release identity are not composed")

    return CliServices(
        audit=lambda _config: AuditFacts(),
        plan=unavailable_plan,
        engine=engine,
        store=store,
        wizard=lambda io, locale, output: TerminalWizard(
            io, locale=locale, config_output=output
        ),
    )


def run(
    argv: Sequence[str] | None,
    *,
    services: CliServices | None = None,
    io: WizardIO | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = _parser().parse_args(argv)
    terminal = io or TerminalIO(sys.stdin, stdout)
    composed = services or _default_services(args.root)
    try:
        if args.command == "wizard":
            return _wizard(args, composed, terminal, stdout)
        if args.command == "plan":
            config, plan = _plan_from_path(args.config, composed)
            del config
            _write_plan(plan, json_output=args.json, output=stdout)
            return 0
        if args.command == "install":
            return _automated_install(args, composed, stdout)
        if args.command == "status":
            _write_status(
                _read_status(composed, args.root),
                json_output=args.json,
                output=stdout,
            )
            return 0
        _adopt_legacy_if_needed(composed, args.root)
        if args.command == "resume":
            state = composed.engine.resume()
        elif args.command == "repair":
            state = composed.engine.repair()
        else:
            state = composed.engine.uninstall(purge_data=args.purge_data)
        _write_status(state, json_output=args.json, output=stdout)
        return 0
    except WizardSaved:
        return 0
    except WizardQuit:
        terminal.write("No changes were made.")
        return 0
    except (
        CliError,
        ConfigError,
        OwnershipError,
        PlanError,
        TransactionError,
        OSError,
        ValueError,
    ) as exc:
        stderr.write(f"BLOCKED: {_bounded_error(exc)}\n")
        stderr.flush()
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


def _wizard(
    args: argparse.Namespace,
    services: CliServices,
    io: WizardIO,
    output: TextIO,
) -> int:
    locale = parse_locale(args.lang) if args.lang else None
    wizard = services.wizard(io, locale, args.config_output)
    preliminary_facts = services.audit(None)
    try:
        config = wizard.run(preliminary_facts)
    except WizardSaved:
        raise
    except WizardQuit:
        selected_locale = getattr(wizard, "locale", None)
        if not isinstance(selected_locale, Locale):
            selected_locale = locale or Locale.EN
        io.write(text(selected_locale, "quit"))
        return 0
    facts = services.audit(config)
    plan = services.plan(config, facts)
    _validate_plan(config, facts, plan)
    _write_plan_summary(plan, io)
    selected_locale = getattr(wizard, "locale", None)
    if not isinstance(selected_locale, Locale):
        selected_locale = locale or Locale.EN
    prompt = text(selected_locale, "digest", prefix=plan.digest[:12]) + ": "
    try:
        confirmation = io.read_line(prompt, strip=False)
    except WizardQuit:
        io.write(text(selected_locale, "quit"))
        return 0
    if confirmation.lower() == "quit":
        io.write(text(selected_locale, "quit"))
        return 0
    if not _HEX_12.fullmatch(confirmation) or not secrets.compare_digest(
        confirmation, plan.digest[:12]
    ):
        raise CliError(text(selected_locale, "digest_mismatch"))
    state = services.engine.apply(plan, accepted_digest=plan.digest)
    _write_status(state, json_output=args.json, output=output)
    return 0


def _automated_install(
    args: argparse.Namespace,
    services: CliServices,
    output: TextIO,
) -> int:
    _config, plan = _plan_from_path(args.config, services)
    accepted = args.accept_plan
    if not _HEX_64.fullmatch(accepted):
        raise CliError("--accept-plan requires the complete plan digest")
    if not secrets.compare_digest(accepted, plan.digest):
        raise CliError("accepted plan digest does not match")
    state = services.engine.apply(plan, accepted_digest=accepted)
    _write_status(state, json_output=args.json, output=output)
    return 0


def _plan_from_path(
    path: Path,
    services: CliServices,
) -> tuple[InstallerConfig, InstallPlan]:
    config = load_config(path)
    facts = services.audit(config)
    plan = services.plan(config, facts)
    _validate_plan(config, facts, plan)
    return config, plan


def _validate_plan(
    config: InstallerConfig,
    facts: AuditFacts,
    plan: InstallPlan,
) -> None:
    canonical = json.loads(plan.to_canonical_json())
    if canonical["config"] != config.canonical_dict():
        raise CliError("planner returned a plan for a different configuration")
    plan.assert_fresh(facts)


def _write_plan(plan: InstallPlan, *, json_output: bool, output: TextIO) -> None:
    if json_output:
        payload = json.loads(plan.to_canonical_json())
        payload["digest"] = plan.digest
        output.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    else:
        output.write(f"plan_digest: {plan.digest}\n")
        for action in plan.actions:
            output.write(f"{action.id}: {', '.join(action.mutations)}\n")
    output.flush()


def _write_plan_summary(plan: InstallPlan, io: WizardIO) -> None:
    io.write("Plan / План")
    io.write(f"digest | {plan.digest}")
    for action in plan.actions:
        io.write(f"{action.id} | {', '.join(action.mutations)}")
        io.write(f"rollback:{action.id} | {', '.join(action.inverse)}")


def _sanitized_status(state: TransactionState) -> dict[str, object]:
    checkpoints = [
        {
            "action_id": checkpoint.action_id,
            "adapter": checkpoint.adapter,
            "phase": checkpoint.phase,
            "success": bool(
                isinstance(checkpoint.evidence, Mapping)
                and checkpoint.evidence.get("success") is True
            ),
        }
        for checkpoint in state.checkpoints
    ]
    payload: dict[str, object] = {
        "checkpoints": checkpoints,
        "origin": state.origin,
        "plan_digest": state.plan_digest,
        "schema": state.schema,
        "status": state.status,
    }
    if state.error is not None:
        payload["error"] = _bounded_text(state.error)
    return payload


def _write_status(state: TransactionState, *, json_output: bool, output: TextIO) -> None:
    payload = _sanitized_status(state)
    if json_output:
        output.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    else:
        output.write(f"status: {payload['status']}\n")
        output.write(f"plan_digest: {payload['plan_digest']}\n")
        output.write(f"origin: {payload['origin']}\n")
        if "error" in payload:
            output.write(f"error: {payload['error']}\n")
    output.flush()


def _read_status(services: CliServices, root: Path) -> TransactionState:
    try:
        return services.store.read_state()
    except TransactionError:
        legacy = _read_legacy(root)
        if legacy is None:
            raise CliError("no installer transaction exists") from None
        digest = str(legacy.get("plan_digest", ""))
        if not _HEX_64.fullmatch(digest):
            digest = "0" * 64
        status = str(legacy.get("status", "unknown"))
        if status not in {
            "active",
            "applying",
            "rolling_back",
            "rollback_failed",
            "rolled_back",
            "uninstalling",
            "uninstalled",
        }:
            status = "rollback_failed"
        return TransactionState(
            transaction_id="0" * 32,
            status=status,
            plan_digest=digest,
            accepted_digest=digest,
            origin="runtime-v2-unimported",
            error="legacy transaction requires import",
        )


def _adopt_legacy_if_needed(services: CliServices, root: Path) -> None:
    try:
        services.store.read_state()
        return
    except TransactionError:
        legacy = _read_legacy(root)
        if legacy is None:
            return
    import_runtime_v2(root, legacy)


def _read_legacy(root: Path) -> dict[str, object] | None:
    path = root / _LEGACY_STATE
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError("legacy runtime state is unreadable") from exc
    if not isinstance(value, dict):
        raise CliError("legacy runtime state is invalid")
    return value


def _bounded_error(exc: BaseException) -> str:
    return _bounded_text(str(exc) or type(exc).__name__)


def _bounded_text(value: str) -> str:
    normalized = " ".join(value.replace("\x00", "").split())
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        normalized,
    )
    return redacted[:500]


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CliError", "CliServices", "main", "run"]
