from __future__ import annotations

import os
import re
import sys
import termios
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Protocol, TextIO, TypeVar

from installer.config import ConfigError, parse_config, render_config
from installer.i18n import Locale, locale_from_environment, parse_locale, text
from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import AuditFacts


_ENUM = TypeVar("_ENUM", bound=StrEnum)
_DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+\Z")
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class PromptValidationError(ValueError):
    def __init__(self, message_key: str, **values: object):
        super().__init__(message_key)
        self.message_key = message_key
        self.values = values


class WizardQuit(Exception):
    """The operator explicitly left the wizard before apply."""


class WizardSaved(WizardQuit):
    """The operator exported a validated config without applying it."""

    def __init__(self, config: InstallerConfig, path: Path):
        super().__init__(str(path))
        self.config = config
        self.path = path


class WizardIO(Protocol):
    """Typed prompt boundary; implementations own all terminal echo handling."""
    def set_locale(self, locale: Locale) -> None: ...

    def write(self, value: str = "") -> None: ...

    def read_line(
        self,
        prompt: str,
        *,
        echo: bool = True,
        strip: bool = True,
    ) -> str: ...

    def choose_enum(
        self,
        prompt: str,
        choices: Sequence[_ENUM],
        *,
        default: _ENUM | None = None,
    ) -> _ENUM: ...

    def validated(
        self,
        prompt: str,
        validator: Callable[[str], str],
        *,
        default: str | None = None,
        allow_empty: bool = False,
    ) -> str: ...

    def integer(
        self,
        prompt: str,
        *,
        minimum: int = 1,
        maximum: int = 65535,
        default: int | None = None,
    ) -> int: ...

    def ports(self, prompt: str, *, default: tuple[int, ...] = ()) -> tuple[int, ...]: ...

    def routes(self, prompt: str) -> tuple[tuple[str, int], ...]: ...

    def yes_no(self, prompt: str, *, default: bool = False) -> bool: ...


class TerminalIO:
    """Line-oriented terminal implementation with echo controlled at this boundary."""

    def __init__(
        self,
        input_stream: TextIO = sys.stdin,
        output_stream: TextIO = sys.stdout,
        *,
        locale: Locale = Locale.EN,
    ):
        self.input = input_stream
        self.output = output_stream
        self.locale = locale

    def set_locale(self, locale: Locale) -> None:
        self.locale = locale

    def _feedback(self, message_key: str, **values: object) -> None:
        self.write(text(self.locale, message_key, **values))

    def write(self, value: str = "") -> None:
        self.output.write(value + "\n")
        self.output.flush()

    def read_line(
        self,
        prompt: str,
        *,
        echo: bool = True,
        strip: bool = True,
    ) -> str:
        self.output.write(prompt)
        self.output.flush()
        restore: list[int] | None = None
        descriptor: int | None = None
        if not echo:
            try:
                descriptor = self.input.fileno()
                restore = termios.tcgetattr(descriptor)
                hidden = restore.copy()
                hidden[3] &= ~termios.ECHO
                termios.tcsetattr(descriptor, termios.TCSADRAIN, hidden)
            except (AttributeError, OSError, termios.error):
                restore = None
                descriptor = None
        try:
            value = self.input.readline()
        finally:
            if restore is not None and descriptor is not None:
                termios.tcsetattr(descriptor, termios.TCSADRAIN, restore)
                self.write()
        if value == "":
            raise WizardQuit
        raw = value.removesuffix("\n").removesuffix("\r")
        result = raw.strip() if strip else raw
        if result.lower() in {"quit", "q", "выход"}:
            raise WizardQuit
        return result

    def choose_enum(
        self,
        prompt: str,
        choices: Sequence[_ENUM],
        *,
        default: _ENUM | None = None,
    ) -> _ENUM:
        if not choices:
            raise ValueError("choices must not be empty")
        by_value = {choice.value: choice for choice in choices}
        values = "/".join(by_value)
        suffix = f" [{default.value}]" if default is not None else ""
        while True:
            raw = self.read_line(f"{prompt} ({values}){suffix}: ").strip().lower()
            if not raw and default is not None:
                return default
            if raw == "save-config" and "save" in by_value:
                raw = "save"
            selected = by_value.get(raw)
            if selected is not None:
                return selected
            self._feedback("invalid_choice", choices=values)

    def validated(
        self,
        prompt: str,
        validator: Callable[[str], str],
        *,
        default: str | None = None,
        allow_empty: bool = False,
    ) -> str:
        suffix = f" [{default}]" if default is not None else ""
        while True:
            raw = self.read_line(f"{prompt}{suffix}: ")
            if not raw and allow_empty:
                return ""
            if not raw and default is not None:
                raw = default
            try:
                return validator(raw)
            except PromptValidationError as exc:
                self._feedback(exc.message_key, **exc.values)
            except ValueError:
                self._feedback("invalid_value")

    def integer(
        self,
        prompt: str,
        *,
        minimum: int = 1,
        maximum: int = 65535,
        default: int | None = None,
    ) -> int:
        def validate(value: str) -> str:
            try:
                parsed = int(value, 10)
            except ValueError as exc:
                raise PromptValidationError("invalid_integer") from exc
            if not minimum <= parsed <= maximum:
                raise PromptValidationError(
                    "invalid_range",
                    minimum=minimum,
                    maximum=maximum,
                )
            return str(parsed)

        rendered_default = str(default) if default is not None else None
        return int(self.validated(prompt, validate, default=rendered_default))

    def ports(self, prompt: str, *, default: tuple[int, ...] = ()) -> tuple[int, ...]:
        rendered_default = ",".join(str(port) for port in default) or None

        def validate(value: str) -> str:
            parts = [part.strip() for part in value.split(",")]
            if not parts or any(not part for part in parts):
                raise PromptValidationError("invalid_ports")
            ports: list[int] = []
            for part in parts:
                try:
                    port = int(part, 10)
                except ValueError as exc:
                    raise PromptValidationError("invalid_ports") from exc
                if not 1 <= port <= 65535:
                    raise PromptValidationError("invalid_ports")
                if port in ports:
                    raise PromptValidationError("duplicate_ports")
                ports.append(port)
            return ",".join(str(port) for port in ports)

        value = self.validated(prompt, validate, default=rendered_default)
        return tuple(int(part) for part in value.split(","))

    def routes(self, prompt: str) -> tuple[tuple[str, int], ...]:
        routes: list[tuple[str, int]] = []
        self.write(f"{prompt}: {text(self.locale, 'invalid_route')}")
        while True:
            raw = self.read_line("> ")
            if not raw:
                return tuple(routes)
            try:
                domain, raw_port = raw.split("=", 1)
                normalized = _domain(domain)
                port = int(raw_port, 10)
                if not 1 <= port <= 65535:
                    raise PromptValidationError("invalid_route")
                if normalized in {item[0] for item in routes}:
                    raise PromptValidationError("duplicate_route")
            except PromptValidationError as exc:
                self._feedback(exc.message_key, **exc.values)
                continue
            except (ValueError, TypeError):
                self._feedback("invalid_route")
                continue
            routes.append((normalized, port))

    def yes_no(self, prompt: str, *, default: bool = False) -> bool:
        suffix = "Y/n" if default else "y/N"
        yes = {"y", "yes", "д", "да"}
        no = {"n", "no", "н", "нет"}
        while True:
            raw = self.read_line(f"{prompt} [{suffix}]: ").strip().lower()
            if not raw:
                return default
            if raw in yes:
                return True
            if raw in no:
                return False
            self._feedback("invalid_yes_no")


class ReviewAction(StrEnum):
    APPLY = "apply"
    BACK = "back"
    EDIT = "edit"
    SAVE = "save"
    QUIT = "quit"


class EditField(StrEnum):
    PANEL = "domains.panel"
    MTPROXY = "domains.mtproxy"
    NAIVE = "domains.naive"
    MIERU = "domains.mieru"
    ACME_EMAIL = "acme_email"
    INITIAL_USER = "initial_user"
    MIERU_TCP = "mieru.tcp_ports"
    MIERU_UDP = "mieru.udp_ports"
    XUI_PANEL = "three_xui.panel_domain"
    XUI_TCP = "three_xui.vless_tcp_domain"
    XUI_XHTTP = "three_xui.vless_xhttp_domain"
    XUI_HYSTERIA = "three_xui.hysteria_domain"
    WARP = "three_xui.warp"
    FIREWALL = "firewall.manage_ufw"


class TerminalWizard:
    def __init__(
        self,
        io: WizardIO,
        *,
        locale: Locale | None = None,
        config_output: Path = Path("proxy-control.toml"),
    ):
        self.io = io
        self.locale = locale
        self.config_output = Path(config_output)

    def run(self, facts: AuditFacts) -> InstallerConfig:
        if not isinstance(facts, AuditFacts):
            raise TypeError("facts must be AuditFacts")
        facts.stable_dict()
        default_locale = self.locale or locale_from_environment(
            os.environ.get("LC_ALL") or os.environ.get("LANG")
        )
        self.io.set_locale(default_locale)
        selected = self.io.choose_enum(
            text(default_locale, "language"),
            (Locale.EN, Locale.RU),
            default=default_locale,
        )
        self.locale = parse_locale(selected)
        self.io.set_locale(self.locale)
        self.io.write(text(self.locale, "secrets_notice"))
        values = self._collect()

        while True:
            try:
                config = self._config(values)
            except ConfigError:
                self.io.write(text(self.locale, "invalid_config"))
                self._edit(values)
                continue
            self._review(config)
            action = self.io.choose_enum(
                text(self.locale, "action"),
                tuple(ReviewAction),
                default=ReviewAction.APPLY,
            )
            if action is ReviewAction.APPLY:
                return config
            if action is ReviewAction.QUIT:
                self.io.write(text(self.locale, "quit"))
                raise WizardQuit
            if action is ReviewAction.SAVE:
                self.config_output.write_text(render_config(config), encoding="utf-8")
                self.io.write(text(self.locale, "saved", path=self.config_output))
                raise WizardSaved(config, self.config_output)
            if action is ReviewAction.BACK:
                self._back(values)
            else:
                self._edit(values)

    def _collect(self) -> dict[str, object]:
        assert self.locale is not None
        host_mode = self.io.choose_enum(text(self.locale, "host_mode"), tuple(HostMode))
        profile = self.io.choose_enum(text(self.locale, "profile"), tuple(Profile))
        xui_mode = self.io.choose_enum(
            text(self.locale, "three_xui_mode"), tuple(ThreeXuiMode)
        )
        values: dict[str, object] = {
            "host_mode": host_mode,
            "profile": profile,
            "xui_mode": xui_mode,
            "panel": self.io.validated(text(self.locale, "panel_domain"), _domain),
            "mtproxy": self.io.validated(text(self.locale, "mtproxy_domain"), _domain),
        }
        if profile.includes_naive:
            values["naive"] = self.io.validated(
                text(self.locale, "naive_domain"), _domain
            )
        if profile.includes_mieru:
            values["mieru"] = self.io.validated(
                text(self.locale, "mieru_domain"), _domain
            )
            values["mieru_tcp"] = self.io.ports(text(self.locale, "mieru_tcp_ports"))
            values["mieru_udp"] = self.io.ports(text(self.locale, "mieru_udp_ports"))
        if xui_mode is ThreeXuiMode.MANAGED_NEW:
            values.update(self._managed_xui())
        elif xui_mode is ThreeXuiMode.EXISTING:
            values.update(self._existing_xui())
        values["acme_email"] = self.io.validated(
            text(self.locale, "acme_email"), _email
        )
        values["initial_user"] = self.io.validated(
            text(self.locale, "initial_user"), _safe_name
        )
        values["manage_ufw"] = (
            self.io.yes_no(text(self.locale, "manage_ufw"), default=True)
            if host_mode is HostMode.FRESH
            else False
        )
        return values

    def _managed_xui(self) -> dict[str, object]:
        assert self.locale is not None
        values: dict[str, object] = {
            "xui_panel": self.io.validated(text(self.locale, "xui_panel_domain"), _domain),
            "xui_tcp": self.io.validated(text(self.locale, "xui_vless_tcp_domain"), _domain),
            "xui_xhttp": self.io.validated(
                text(self.locale, "xui_vless_xhttp_domain"), _domain
            ),
            "xui_hysteria": self.io.validated(
                text(self.locale, "xui_hysteria_domain"), _domain
            ),
        }
        warp = self.io.yes_no(text(self.locale, "warp"), default=False)
        values["warp"] = warp
        values["warp_domains"] = (
            self._domains(text(self.locale, "warp_domains")) if warp else ()
        )
        return values

    def _existing_xui(self) -> dict[str, object]:
        assert self.locale is not None
        result: dict[str, object] = {}
        for key, message in (
            ("xui_panel", "xui_panel_domain"),
            ("xui_tcp", "xui_vless_tcp_domain"),
            ("xui_xhttp", "xui_vless_xhttp_domain"),
            ("xui_hysteria", "xui_hysteria_domain"),
        ):
            value = self.io.validated(
                text(self.locale, message), _domain, allow_empty=True
            )
            if value:
                result[key] = value
        return result

    def _domains(self, prompt: str) -> tuple[str, ...]:
        def validate(value: str) -> str:
            domains = tuple(_domain(part) for part in value.split(",") if part.strip())
            if not domains:
                raise PromptValidationError("invalid_domains")
            if len(domains) != len(set(domains)):
                raise PromptValidationError("duplicate_domains")
            return ",".join(domains)

        return tuple(self.io.validated(prompt, validate).split(","))

    def _config(self, values: dict[str, object]) -> InstallerConfig:
        profile = values["profile"]
        xui_mode = values["xui_mode"]
        assert isinstance(profile, Profile)
        assert isinstance(xui_mode, ThreeXuiMode)
        candidate = InstallerConfig(
            schema=1,
            host_mode=values["host_mode"],
            profile=profile,
            acme_email=str(values["acme_email"]),
            initial_user=str(values["initial_user"]),
            domains=DomainConfig(
                panel=str(values["panel"]),
                mtproxy=str(values["mtproxy"]),
                naive=str(values["naive"]) if profile.includes_naive else None,
                mieru=str(values["mieru"]) if profile.includes_mieru else None,
            ),
            mieru=(
                MieruConfig(
                    tcp_ports=values["mieru_tcp"],
                    udp_ports=values["mieru_udp"],
                )
                if profile.includes_mieru
                else None
            ),
            three_xui=ThreeXuiConfig(
                mode=xui_mode,
                panel_domain=_optional(values.get("xui_panel")),
                vless_tcp_domain=_optional(values.get("xui_tcp")),
                vless_xhttp_domain=_optional(values.get("xui_xhttp")),
                hysteria_domain=_optional(values.get("xui_hysteria")),
                warp=bool(values.get("warp", False)),
                warp_domains=values.get("warp_domains", ()),
            ),
            firewall=FirewallConfig(manage_ufw=bool(values["manage_ufw"])),
        )
        return parse_config(render_config(candidate))

    def _review(self, config: InstallerConfig) -> None:
        assert self.locale is not None
        self.io.write()
        self.io.write(text(self.locale, "review_title"))
        self.io.write(text(self.locale, "review_header"))
        for key, value in _flatten(config.canonical_dict()):
            self.io.write(f"{key} | {value}")
        self.io.write(text(self.locale, "secrets_notice"))

    def _editable(self, values: dict[str, object]) -> tuple[EditField, ...]:
        profile = values["profile"]
        xui_mode = values["xui_mode"]
        fields = [
            EditField.PANEL,
            EditField.MTPROXY,
            EditField.ACME_EMAIL,
            EditField.INITIAL_USER,
        ]
        if isinstance(profile, Profile) and profile.includes_naive:
            fields.append(EditField.NAIVE)
        if isinstance(profile, Profile) and profile.includes_mieru:
            fields.extend((EditField.MIERU, EditField.MIERU_TCP, EditField.MIERU_UDP))
        if xui_mode is not ThreeXuiMode.NONE:
            fields.extend(
                (
                    EditField.XUI_PANEL,
                    EditField.XUI_TCP,
                    EditField.XUI_XHTTP,
                    EditField.XUI_HYSTERIA,
                )
            )
        if xui_mode is ThreeXuiMode.MANAGED_NEW:
            fields.append(EditField.WARP)
        if values["host_mode"] is HostMode.FRESH:
            fields.append(EditField.FIREWALL)
        return tuple(fields)

    def _edit(self, values: dict[str, object]) -> None:
        assert self.locale is not None
        field = self.io.choose_enum(
            text(self.locale, "edit_field"), self._editable(values)
        )
        self._prompt_field(values, field)

    def _back(self, values: dict[str, object]) -> None:
        self._prompt_field(values, self._editable(values)[-1])

    def _prompt_field(self, values: dict[str, object], field: EditField) -> None:
        assert self.locale is not None
        domains = {
            EditField.PANEL: ("panel", "panel_domain"),
            EditField.MTPROXY: ("mtproxy", "mtproxy_domain"),
            EditField.NAIVE: ("naive", "naive_domain"),
            EditField.MIERU: ("mieru", "mieru_domain"),
            EditField.XUI_PANEL: ("xui_panel", "xui_panel_domain"),
            EditField.XUI_TCP: ("xui_tcp", "xui_vless_tcp_domain"),
            EditField.XUI_XHTTP: ("xui_xhttp", "xui_vless_xhttp_domain"),
            EditField.XUI_HYSTERIA: ("xui_hysteria", "xui_hysteria_domain"),
        }
        if field in domains:
            key, message = domains[field]
            optional = (
                values["xui_mode"] is ThreeXuiMode.EXISTING
                and field
                in {
                    EditField.XUI_PANEL,
                    EditField.XUI_TCP,
                    EditField.XUI_XHTTP,
                    EditField.XUI_HYSTERIA,
                }
            )
            values[key] = self.io.validated(
                text(self.locale, message),
                _domain,
                default=_optional(values.get(key)),
                allow_empty=optional,
            )
        elif field is EditField.ACME_EMAIL:
            values["acme_email"] = self.io.validated(
                text(self.locale, "acme_email"), _email, default=str(values["acme_email"])
            )
        elif field is EditField.INITIAL_USER:
            values["initial_user"] = self.io.validated(
                text(self.locale, "initial_user"),
                _safe_name,
                default=str(values["initial_user"]),
            )
        elif field is EditField.MIERU_TCP:
            values["mieru_tcp"] = self.io.ports(
                text(self.locale, "mieru_tcp_ports"), default=values["mieru_tcp"]
            )
        elif field is EditField.MIERU_UDP:
            values["mieru_udp"] = self.io.ports(
                text(self.locale, "mieru_udp_ports"), default=values["mieru_udp"]
            )
        elif field is EditField.WARP:
            values["warp"] = self.io.yes_no(
                text(self.locale, "warp"), default=bool(values.get("warp", False))
            )
            values["warp_domains"] = (
                self._domains(text(self.locale, "warp_domains")) if values["warp"] else ()
            )
        else:
            values["manage_ufw"] = self.io.yes_no(
                text(self.locale, "manage_ufw"), default=bool(values["manage_ufw"])
            )


def _domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(normalized):
        raise PromptValidationError("invalid_domain")
    return normalized


def _email(value: str) -> str:
    normalized = value.strip()
    if not _EMAIL_RE.fullmatch(normalized):
        raise PromptValidationError("invalid_email")
    return normalized


def _safe_name(value: str) -> str:
    normalized = value.strip()
    if not _SAFE_NAME_RE.fullmatch(normalized):
        raise PromptValidationError("invalid_name")
    return normalized


def _optional(value: object) -> str | None:
    return str(value) if value is not None and str(value) else None


def _flatten(value: object, prefix: str = "") -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else key
            rows.extend(_flatten(value[key], path))
    elif isinstance(value, list):
        rows.append((prefix, ",".join(str(item) for item in value)))
    else:
        rows.append((prefix, str(value).lower() if isinstance(value, bool) else str(value)))
    return tuple(rows)


__all__ = [
    "TerminalIO",
    "TerminalWizard",
    "WizardIO",
    "WizardQuit",
    "WizardSaved",
]
