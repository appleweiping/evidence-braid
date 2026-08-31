from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from evidence_braid.models import EvidenceEvent, Policy

BASE_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "policy_id": "test-policy",
    "default_source_reliability": 0.8,
    "sources": {
        "camera-a": {"reliability": 1.0},
        "microphone-a": {"reliability": 0.9},
        "operator-a": {"reliability": 0.95},
    },
    "decay": {
        "default_half_life_seconds": 60,
        "modality_half_life_seconds": {"sensor": 120},
        "max_future_skew_seconds": 2,
    },
    "claims": {
        "incident": {
            "support_threshold": 0.7,
            "contradiction_threshold": 0.7,
            "min_margin": 0.1,
            "quorum": 2,
            "min_sources": 2,
            "min_modalities": 2,
            "min_evidence_confidence": 0.2,
        }
    },
}


def policy_dict(**claim_overrides: Any) -> dict[str, Any]:
    raw = deepcopy(BASE_POLICY)
    raw["claims"]["incident"].update(claim_overrides)
    return raw


def event_dict(event_id: str = "e1", **overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "event_id": event_id,
        "claim": "incident",
        "modality": "vision",
        "source": "camera-a",
        "signal": "support",
        "confidence": 0.9,
        "observed_at": "2026-08-31T11:59:30Z",
        "ingested_at": "2026-08-31T11:59:31Z",
    }
    raw.update(overrides)
    return raw


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(policy_dict())


@pytest.fixture
def make_event():
    def factory(event_id: str = "e1", **overrides: Any) -> EvidenceEvent:
        return EvidenceEvent.from_dict(event_dict(event_id, **overrides))

    return factory
