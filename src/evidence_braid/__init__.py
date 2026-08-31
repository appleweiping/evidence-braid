"""Evidence Braid public API."""

from .engine import ClaimDecision, EvaluationResult, evaluate
from .errors import EvidenceBraidError, InputFormatError, ValidationError
from .models import EvidenceEvent, Modality, Outcome, Policy, Signal
from .replay import replay
from .report import render_html, render_svg

__all__ = [
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
    "evaluate",
    "render_html",
    "render_svg",
    "replay",
]

__version__ = "0.1.0"
