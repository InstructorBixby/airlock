"""Load and interpret the routing policy.

Policy is data. That is the point of the file: the question "what is
allowed to leave this machine" has to be answerable by reading one
document, not by reading control flow in a request handler.

The loader is strict and unhelpful on purpose. Every validation error
here is a configuration that would have been fail-open, so there is no
"warn and continue" path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from airlock import tiers


class PolicyError(Exception):
    pass


#: Requirements a route may declare.
KNOWN_REQUIREMENTS = {"redacted", "local", "available"}


@dataclass(frozen=True)
class Route:
    backend: str
    require: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.require:
            return f"{self.backend} (requires {', '.join(self.require)})"
        return self.backend


@dataclass(frozen=True)
class Backend:
    name: str
    kind: str
    base_url: str
    api_key_env: str | None = None
    models: dict = field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        host = self.base_url.split("//", 1)[-1].split("/", 1)[0]
        host = host.split(":", 1)[0]
        return host in ("127.0.0.1", "localhost", "::1", "[::1]")

    def api_key(self) -> str:
        if not self.api_key_env:
            return ""
        return os.environ.get(self.api_key_env, "")

    def model_for(self, requested: str | None) -> str:
        if requested and requested in self.models:
            return self.models[requested]
        return self.models.get("default") or requested or ""


@dataclass
class Policy:
    routes: dict = field(default_factory=dict)
    backends: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    source: str = "<memory>"

    def candidates(self, tier: str) -> list[Route]:
        return list(self.routes.get(tier, ()))

    def backend(self, name: str) -> Backend:
        try:
            return self.backends[name]
        except KeyError as exc:
            raise PolicyError(f"no backend named {name!r}") from exc


def _parse_backends(raw: dict) -> dict:
    out = {}
    for name, body in (raw or {}).items():
        if not isinstance(body, dict):
            raise PolicyError(f"backend {name!r} is not a mapping")
        missing = {"kind", "base_url"} - set(body)
        if missing:
            raise PolicyError(f"backend {name!r} missing "
                              f"{sorted(missing)}")
        out[name] = Backend(
            name=name, kind=body["kind"], base_url=body["base_url"],
            api_key_env=body.get("api_key_env"),
            models=dict(body.get("models") or {}),
        )
    if not out:
        raise PolicyError("policy declares no backends")
    return out


def _parse_routes(raw: dict, backends: dict) -> dict:
    out = {}
    for tier, body in (raw or {}).items():
        if tier not in tiers.ORDER and tier != tiers.UNDECIDED:
            raise PolicyError(f"unknown tier {tier!r}")
        routes = []
        for item in body or []:
            if not isinstance(item, dict) or "backend" not in item:
                raise PolicyError(f"{tier}: route is not a mapping "
                                  f"with a backend")
            require = tuple(item.get("require") or ())
            unknown = set(require) - KNOWN_REQUIREMENTS
            if unknown:
                raise PolicyError(f"{tier}: unknown requirement(s) "
                                  f"{sorted(unknown)}")
            if item["backend"] not in backends:
                raise PolicyError(f"{tier}: route to undeclared "
                                  f"backend {item['backend']!r}")
            routes.append(Route(item["backend"], require))
        out[tier] = routes
    return out


def _check_invariants(pol: Policy) -> None:
    # The one rule the file cannot be allowed to express.
    for route in pol.candidates(tiers.CONFIDENTIAL):
        be = pol.backend(route.backend)
        if not be.is_local:
            raise PolicyError(
                f"client-confidential routed to {be.name!r}, whose "
                f"base_url is not on this machine. The policy "
                f"language does not permit this.")
    if pol.candidates(tiers.UNDECIDED):
        raise PolicyError("undecided has a route; it cannot have one")
    for tier in tiers.ORDER:
        if tier not in pol.routes:
            raise PolicyError(f"policy says nothing about {tier!r}; "
                              f"silence is not a default")


def load(path) -> Policy:
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"no policy at {p}")
    raw = yaml.safe_load(p.read_text()) or {}
    if raw.get("version") != 1:
        raise PolicyError(f"{p}: unsupported policy version "
                          f"{raw.get('version')!r}")
    backends = _parse_backends(raw.get("backends"))
    pol = Policy(routes=_parse_routes(raw.get("routes"), backends),
                 backends=backends,
                 limits=dict(raw.get("limits") or {}),
                 source=str(p))
    _check_invariants(pol)
    return pol


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "airlock" / "policy.yaml"
    return Path.home() / ".config" / "airlock" / "policy.yaml"
