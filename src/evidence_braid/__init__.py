"""Evidence Braid public API."""

from .baselines import BaselineDecision, majority_vote, reliability_weighted_vote
from .engine import ClaimDecision, EvaluationResult, evaluate
from .errors import EvidenceBraidError, InputFormatError, ValidationError
from .ledger import EvidenceLedger, LedgerEntry, build_ledger
from .metrics import classification_metrics
from .models import Adjudication, EvidenceEvent, Modality, Outcome, Policy, Signal, Verdict
from .provenance import ProvenanceEdge, ProvenanceGraph, ProvenanceNode, build_provenance
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
    "EvidenceLedger",
    "InputFormatError",
    "LedgerEntry",
    "Modality",
    "Outcome",
    "Policy",
    "ProvenanceEdge",
    "ProvenanceGraph",
    "ProvenanceNode",
    "RobustnessImpact",
    "RobustnessReport",
    "Signal",
    "ValidationError",
    "Verdict",
    "analyze_robustness",
    "build_ledger",
    "build_provenance",
    "classification_metrics",
    "evaluate",
    "majority_vote",
    "reliability_weighted_vote",
    "render_html",
    "render_svg",
    "replay",
    "robustness",
]

__version__ = "0.5.0"
