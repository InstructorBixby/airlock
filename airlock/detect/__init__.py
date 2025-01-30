"""Detectors.

A detector is a callable that takes text and yields Findings. That is
the entire contract: no state, no network, no knowledge of policy.

Registration order does not matter because an Assessment takes the
most restrictive tier anything reported, so detectors cannot race each
other to a verdict.
"""
from __future__ import annotations

from typing import Callable, Iterator

from airlock.model import Finding

Detector = Callable[[str], Iterator[Finding]]

REGISTRY: dict[str, Detector] = {}


def register(name: str):
    def deco(fn: Detector) -> Detector:
        REGISTRY[name] = fn
        return fn
    return deco


def load_builtins() -> None:
    from airlock.detect import net, secrets  # noqa: F401


def all_detectors() -> dict:
    load_builtins()
    return dict(REGISTRY)
