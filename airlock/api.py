"""The supported surface.

Importing from `airlock.api` is the only thing covered by the stability
policy in docs/stability.md. Everything else in the package is internal
and will move: the detector registry, the server internals, the way the
scrub map is laid out on disk.

The surface is small on purpose. It is the three things somebody
embedding this actually needs -- classify some text, ask the policy
where it would go, and start the gateway -- plus the vocabulary needed
to read the answers.
"""
from __future__ import annotations

from airlock import __version__
from airlock.audit import Log, Record
from airlock.classify import classify_request, classify_text
from airlock.engagement import Engagement, EngagementError
from airlock.model import Assessment, Finding
from airlock.policy import Policy, PolicyError
from airlock.policy import load as load_policy
from airlock.route import Decision, decide
from airlock.server import Gateway, serve
from airlock.tiers import CONFIDENTIAL, INTERNAL, PUBLIC, UNDECIDED

__all__ = [
    "__version__",
    # vocabulary
    "PUBLIC", "INTERNAL", "CONFIDENTIAL", "UNDECIDED",
    # classification
    "Assessment", "Finding", "classify_text", "classify_request",
    # policy and routing
    "Policy", "PolicyError", "load_policy", "Decision", "decide",
    # running it
    "Gateway", "serve",
    # evidence
    "Log", "Record",
    # engagements
    "Engagement", "EngagementError",
]
