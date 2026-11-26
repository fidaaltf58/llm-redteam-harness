"""Turn per-run booleans into success rates with honest uncertainty.

With 5 runs per case, "2/5 = 40%" has a very wide confidence interval. We report the count
(k/n) and the Wilson score interval, which behaves well for small n and for rates near 0 or 1
(unlike the normal approximation, which can produce intervals below 0% or above 100%).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass

from redteam.models import CaseResult


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def finalize_case(result: CaseResult) -> CaseResult:
    """Fill successes/trials/rate/CI from the run records. Errored runs are not trials."""
    valid = [r for r in result.runs if r.error is None]
    result.errors = len(result.runs) - len(valid)
    result.trials = len(valid)
    result.successes = sum(r.success for r in valid)
    attempts = [r.attempted for r in valid if r.attempted is not None]
    result.attempts = sum(attempts) if attempts else None
    if result.trials:
        result.rate = result.successes / result.trials
        result.ci_low, result.ci_high = wilson_interval(result.successes, result.trials)
    else:
        result.rate = result.ci_low = result.ci_high = None
    return result


@dataclass
class GroupStats:
    key: str
    cases: int = 0
    cases_with_success: int = 0
    successes: int = 0
    trials: int = 0

    @property
    def rate(self) -> float | None:
        return self.successes / self.trials if self.trials else None

    @property
    def ci(self) -> tuple[float, float]:
        return wilson_interval(self.successes, self.trials)


def group_by(cases: list[CaseResult], key: str) -> dict[str, GroupStats]:
    """Pool runs by ``owasp`` (primary + secondary IDs), ``owasp_llm`` (primary only),
    ``category`` or ``atlas``. A case mapped to several IDs counts once under each."""
    groups: dict[str, GroupStats] = defaultdict(lambda: GroupStats(key=""))
    for c in cases:
        if c.skipped or not c.trials:
            continue
        if key == "atlas":
            keys = c.atlas
        elif key == "owasp":
            keys = list(dict.fromkeys([c.owasp_llm, *c.owasp_secondary]))
        else:
            keys = [getattr(c, key)]
        for k in keys:
            g = groups[k]
            g.key = k
            g.cases += 1
            g.cases_with_success += int(c.successes > 0)
            g.successes += c.successes
            g.trials += c.trials
    return dict(sorted(groups.items()))


def overall(cases: list[CaseResult]) -> GroupStats:
    g = GroupStats(key="overall")
    for c in cases:
        if c.skipped or not c.trials:
            continue
        g.cases += 1
        g.cases_with_success += int(c.successes > 0)
        g.successes += c.successes
        g.trials += c.trials
    return g
