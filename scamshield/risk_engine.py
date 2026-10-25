"""Transparent risk scoring. The score is an INDICATIVE RISK INDEX (0-100), not a probability.

Anti double-counting: indicators share a `group`; only the highest-point indicator of each
group is awarded points, related signals in the same group are shown with 0 awarded points.
A small corroboration bonus is added when several independent groups fire.
"""
from dataclasses import dataclass, asdict

LEVELS = [(75, "Critical"), (50, "High"), (25, "Moderate"), (0, "Low")]
LEVEL_COLORS = {"Low": "#15803D", "Moderate": "#B45309", "High": "#C2410C", "Critical": "#B91C1C"}

LIMITATIONS = (
    "This score is an indicative risk index based on transparent warning patterns. It is not a calibrated "
    "probability of fraud and not a legal or forensic finding. A low score does not mean content is safe, "
    "and a high score does not prove fraud. No website was visited and no domain ownership, DNS or reputation "
    "data was verified. Always confirm through official channels."
)


@dataclass
class Indicator:
    id: str
    name: str
    group: str
    points: int
    evidence: str
    why: str
    awarded: int = 0


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def score_indicators(indicators):
    """Returns (score, indicators_as_dicts). Mutates `awarded` on indicators."""
    best = {}
    for ind in indicators:
        ind.awarded = 0
        if ind.group not in best or ind.points > best[ind.group].points:
            best[ind.group] = ind
    for ind in best.values():
        ind.awarded = ind.points
    base = sum(i.awarded for i in best.values())
    n = len(best)
    out = [asdict(i) for i in sorted(indicators, key=lambda i: (-i.awarded, -i.points))]
    bonus = 10 if n >= 5 else 6 if n >= 3 else 0
    if bonus:
        out.append(asdict(Indicator(
            "corroboration", "Multiple independent warning signals", "bonus", bonus,
            f"{n} different warning groups detected",
            "Several unrelated red flags appearing together is more concerning than any one alone.", bonus)))
    total = min(100, base + bonus)
    return total, out
