"""Telemt has no operation id, so a lost response is recovered by reading the truth back.

Telemt's API is not idempotent and cannot be made so from the panel side. What it does
offer is that the live link *is* the credential: after a request whose reply never
arrived, reading the user back tells the panel exactly what the runtime now holds.
"""

from __future__ import annotations


import pytest

from panel.tests.harness.memories.telemt import MemoryTelemt, TelemtIndeterminate

pytestmark = pytest.mark.anyio





@pytest.fixture
def telemt():
    return MemoryTelemt(public_host="proxy.example.com", public_port=443)


















