"""Port interfaces (coding spec §6) - core/business modules depend only on
these; adapters implement them (hexagonal architecture).

This package is intentionally thin: each Protocol is a structural contract,
not a base class - Python Protocols are satisfied by matching shape, not by
inheritance, so existing implementations elsewhere in the codebase conform
without importing from here. Where a concrete implementation already lives in
its own module (SignerPort in gate/service.py, MarketplacePort in
integration_relay/marketplace.py) it has been moved HERE and re-exported from
its original location, so existing import sites keep working unchanged.
"""

from __future__ import annotations

from ports.detection_engine import DetectionEnginePort
from ports.intel import IntelPort
from ports.llm import LLMPort
from ports.marketplace import MarketplacePort
from ports.notification import NotificationPort
from ports.repository import RepositoryPort
from ports.signer import SignerPort

__all__ = [
    "DetectionEnginePort",
    "IntelPort",
    "LLMPort",
    "MarketplacePort",
    "NotificationPort",
    "RepositoryPort",
    "SignerPort",
]
