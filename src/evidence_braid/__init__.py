"""Evidence Braid public API."""

from .baselines import BaselineDecision, majority_vote, reliability_weighted_vote
from .engine import ClaimDecision, EvaluationResult, evaluate
from .errors import EvidenceBraidError, InputFormatError, ValidationError
from .metrics import classification_metrics
from .models import EvidenceEvent, Modality, Outcome, Policy, Signal
from .replay import replay
from .report import render_html, render_svg

__all__ = [
    "BaselineDecision",
    "ClaimDecision",
    "EvaluationResult",
    "EvidenceBraidError",
    "EvidenceEvent",
    "InputFormatError",
    "Modality",
    "Outcome",
    "Policy",
    "Signal",
    "ValidationError",
    "classification_metrics",
    "evaluate",
    "majority_vote",
    "reliability_weighted_vote",
    "render_html",
    "render_svg",
    "replay",
]

__version__ = "0.2.0"
