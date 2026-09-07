"""Evidence Braid public API."""

from .baselines import BaselineDecision, majority_vote, reliability_weighted_vote
from .engine import ClaimDecision, EvaluationResult, evaluate
from .errors import EvidenceBraidError, InputFormatError, ValidationError
from .metrics import classification_metrics
from .models import Adjudication, EvidenceEvent, Modality, Outcome, Policy, Signal, Verdict
from .replay import replay
from .report import render_html, render_svg
from .robustness import (
    ClaimRobustness,
    RobustnessImpact,
    RobustnessReport,
    analyze_robustness,
    robustness,
)

__all__ = [
    "Adjudication",
    "BaselineDecision",
    "ClaimDecision",
    "ClaimRobustness",
    "EvaluationResult",
    "EvidenceBraidError",
    "EvidenceEvent",
    "InputFormatError",
    "Modality",
    "Outcome",
    "Policy",
    "RobustnessImpact",
    "RobustnessReport",
    "Signal",
    "ValidationError",
    "Verdict",
    "analyze_robustness",
    "classification_metrics",
    "evaluate",
    "majority_vote",
    "reliability_weighted_vote",
    "render_html",
    "render_svg",
    "replay",
    "robustness",
]

__version__ = "0.4.0"
