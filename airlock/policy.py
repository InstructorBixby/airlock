"""Load and interpret the routing policy.

Policy is data. That is the point of the file: the question "what is
allowed to leave this machine" has to be answerable by reading one
document, not by reading control flow in a request handler.

The loader is strict and unhelpful on purpose. Every validation error
here is a configuration that would have been fail-open, so there is no
"warn and continue" path. The one exception is a deprecated key, which
is migrated with a warning rather than rejected -- an engagement's
policy file from before a rename has to keep loading, because the
alternative is that I edit it in a hurry on the day I need it.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from airlock import deprecations, tiers
from airlock.cost import Price


class PolicyError(Exception):
    pass


KNOWN_REQUIREMENTS = {"redacted", "local", "available"}

BACKEND_KEYS = {"kind", "base_url", "api_key_env", "models", "prices",
                "preserve_model", "timeout", "default_model"}


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
    default_model: str = ""
    models: dict = field(default_factory=dict)
    prices: dict = field(default_factory=dict)
    #: when the clients already name a model this backend serves, so
    #: the gateway should not rewrite the field and can forward the
    #: original bytes. See docs/caching.md.
    preserve_model: bool = False
    timeout: float = 180.0

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
        if self.preserve_model and requested:
            return requested
        if requested and requested in self.models:
            return self.models[requested]
        return self.default_model or requested or ""


@dataclass
class Policy:
    routes: dict = field(default_factory=dict)
    backends: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    source: str = "<memory>"
    digest: str = ""

    def candidates(self, tier: str) -> list[Route]:
        return list(self.routes.get(tier, ()))

    def backend(self, name: str) -> Backend:
        try:
            return self.backends[name]
        except KeyError as exc:
            raise PolicyError(f"no backend named {name!r}") from exc

    @property
    def max_outbound_chars(self) -> int:
        return int(self.limits.get("max_outbound_chars") or 0)

    @property
    def max_cost_usd(self) -> float | None:
        v = self.limits.get("max_cost_usd")
        return float(v) if v is not None else None


def _parse_backends(raw: dict) -> dict:
    out = {}
    for name, body in (raw or {}).items():
        if not isinstance(body, dict):
            raise PolicyError(f"backend {name!r} is not a mapping")
        try:
            body = deprecations.migrate_backend(name, body)
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc
        missing = {"kind", "base_url"} - set(body)
        if missing:
            raise PolicyError(f"backend {name!r} missing "
                              f"{sorted(missing)}")
        unknown = set(body) - BACKEND_KEYS
        if unknown:
            raise PolicyError(f"backend {name!r}: unknown key(s) "
                              f"{sorted(unknown)}")
        prices = {}
        for model, p in (body.get("prices") or {}).items():
            parsed = Price.from_raw(p)
            if parsed is None:
                raise PolicyError(f"backend {name!r}: price for "
                                  f"{model!r} is empty")
            prices[model] = parsed
        out[name] = Backend(
            name=name, kind=body["kind"], base_url=body["base_url"],
            api_key_env=body.get("api_key_env"),
            default_model=str(body.get("default_model") or ""),
            models=dict(body.get("models") or {}),
            prices=prices,
            preserve_model=bool(body.get("preserve_model")),
            timeout=float(body.get("timeout") or 180.0),
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


def loads(text: str, *, source: str = "<string>") -> Policy:
    raw = yaml.safe_load(text) or {}
    if raw.get("version") != 1:
        raise PolicyError(f"{source}: unsupported policy version "
                          f"{raw.get('version')!r}")
    backends = _parse_backends(raw.get("backends"))
    pol = Policy(routes=_parse_routes(raw.get("routes"), backends),
                 backends=backends,
                 limits=dict(raw.get("limits") or {}),
                 source=source,
                 # The digest is of the file as written, before
                 # migration, so a record points at the bytes on disk.
                 digest="sha256:" + hashlib.sha256(
                     text.encode("utf-8")).hexdigest())
    _check_invariants(pol)
    return pol


def load(path) -> Policy:
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"no policy at {p}")
    return loads(p.read_text(), source=str(p))


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "airlock" / "policy.yaml"
    return Path.home() / ".config" / "airlock" / "policy.yaml"
