from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from installer.adapters.base import Adapter

if TYPE_CHECKING:
    from installer.adapters.core import CoreAcceptance, CoreAdapter, CorePaths
    from installer.adapters.firewall import FirewallAdapter
    from installer.adapters.mieru import MieruAcceptance, MieruAdapter, MieruPaths
    from installer.adapters.naive import NaiveAcceptance, NaiveAdapter, NaivePaths
    from installer.adapters.nginx import CertificatePlan, NginxAdapter
    from installer.adapters.packages import PackagesAdapter


_EXPORTS = {
    "CertificatePlan": ("installer.adapters.nginx", "CertificatePlan"),
    "CoreAcceptance": ("installer.adapters.core", "CoreAcceptance"),
    "CoreAdapter": ("installer.adapters.core", "CoreAdapter"),
    "CorePaths": ("installer.adapters.core", "CorePaths"),
    "FirewallAdapter": ("installer.adapters.firewall", "FirewallAdapter"),
    "MieruAcceptance": ("installer.adapters.mieru", "MieruAcceptance"),
    "MieruAdapter": ("installer.adapters.mieru", "MieruAdapter"),
    "MieruPaths": ("installer.adapters.mieru", "MieruPaths"),
    "NaiveAcceptance": ("installer.adapters.naive", "NaiveAcceptance"),
    "NaiveAdapter": ("installer.adapters.naive", "NaiveAdapter"),
    "NaivePaths": ("installer.adapters.naive", "NaivePaths"),
    "NginxAdapter": ("installer.adapters.nginx", "NginxAdapter"),
    "PackagesAdapter": ("installer.adapters.packages", "PackagesAdapter"),
}


def __getattr__(name: str) -> object:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value


__all__ = [
    "Adapter",
    "CertificatePlan",
    "CoreAcceptance",
    "CoreAdapter",
    "CorePaths",
    "FirewallAdapter",
    "MieruAcceptance",
    "MieruAdapter",
    "MieruPaths",
    "NaiveAcceptance",
    "NaiveAdapter",
    "NaivePaths",
    "NginxAdapter",
    "PackagesAdapter",
]
