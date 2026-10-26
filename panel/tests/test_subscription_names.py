"""Human names distinguish fleet nodes without changing connection credentials."""
import dataclasses
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from panel.protocols.base import AccessArtifact
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import RENDERERS
from panel.subscriptions.service import SubscriptionService


def feed(protocol="naive", names=("AMS_P", "AMS_Z")):
    grants, artifacts = [], {}
    for index, name in enumerate(names):
        grant = ManifestGrant(
            grant_id=f"grant-{index}", protocol=protocol, node_id=f"node-{index}",
            endpoint_id="default", runtime_username="throne-android", secret_version=1,
            options={}, enabled=True, node_name=name,
        )
        grants.append(grant)
        link = (f"https://user:fake-password@node{index}.example:443" if protocol == "naive" else
                f"mierus://user:fake-password@node{index}.example?profile=old&port=8443&protocol=TCP&mtu=1400")
        artifacts[grant.grant_id] = [AccessArtifact("link", "Connection", "text/uri-list", link)]
    return Manifest("client", "throne-android", 1, grants), artifacts



























