"""Counting, with honest error bars."""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Rate:
    """A proportion with its 95% Wilson score interval."""

    hits: int
    total: int

    @property
    def value(self) -> float:
        return self.hits / self.total if self.total else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        """95% Wilson interval. Unlike the naive one, it behaves at 0% and 100%."""
        if not self.total:
            return (0.0, 0.0)
        z = 1.959963984540054
        n = self.total
        p = self.hits / n
        denominator = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denominator
        margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
        low = 0.0 if self.hits == 0 else max(0.0, centre - margin)
        high = 1.0 if self.hits == n else min(1.0, centre + margin)
        return (low, high)

    def as_dict(self) -> dict[str, float | int]:
        low, high = self.interval
        return {
            "hits": self.hits,
            "total": self.total,
            "rate": round(self.value, 4),
            "ci95_low": round(low, 4),
            "ci95_high": round(high, 4),
        }

    def __str__(self) -> str:
        low, high = self.interval
        return f"{self.value:.1%} ({self.hits}/{self.total}, 95% CI {low:.1%}-{high:.1%})"
