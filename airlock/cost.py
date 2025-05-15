"""Token cost arithmetic.

Prices live in policy, not here, because they change and a hardcoded
price table silently becomes a lie. A backend with no prices declared
contributes zero to the total and says so, rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    #: dollars per million tokens
    prompt: float = 0.0
    completion: float = 0.0

    @classmethod
    def from_raw(cls, raw) -> "Price | None":
        if not raw:
            return None
        return cls(prompt=float(raw.get("prompt", 0.0)),
                   completion=float(raw.get("completion", 0.0)))

    def of(self, prompt_tokens: int, completion_tokens: int) -> float:
        return round(
            (prompt_tokens * self.prompt
             + completion_tokens * self.completion) / 1_000_000, 6)


def estimate(prices: dict, model: str, usage: dict) -> float | None:
    """None means "no price declared", which is not the same as free."""
    price = prices.get(model) or prices.get("default")
    if price is None:
        return None
    return price.of(int(usage.get("prompt") or 0),
                    int(usage.get("completion") or 0))
