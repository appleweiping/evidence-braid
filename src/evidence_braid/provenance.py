"""Explicit claim/source/event provenance graph construction."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from .errors import ValidationError
from .models import EvidenceEvent

NodeKind = Literal["claim", "source", "event", "correlation"]


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    id: str
    kind: NodeKind
    label: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "kind": self.kind, "label": self.label}


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    source: str
    target: str
    relation: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "target": self.target, "relation": self.relation}


@dataclass(frozen=True, slots=True)
class ProvenanceGraph:
    nodes: tuple[ProvenanceNode, ...]
    edges: tuple[ProvenanceEdge, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "evidence-braid-provenance",
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def trace_claim(self, claim: str) -> tuple[ProvenanceNode, ...]:
        """Return the claim and all directly connected evidence/source nodes."""

        target = f"claim:{claim}"
        neighbors = {target}
        for edge in self.edges:
            if edge.target == target or edge.source == target:
                neighbors.add(edge.source)
                neighbors.add(edge.target)
        return tuple(node for node in self.nodes if node.id in neighbors)


def build_provenance(events: Iterable[EvidenceEvent]) -> ProvenanceGraph:
    """Build a stable bipartite source/event/claim graph with correlation links."""

    supplied = list(events)
    if any(not isinstance(event, EvidenceEvent) for event in supplied):
        raise ValidationError("provenance events must be EvidenceEvent instances")
    if len({event.event_id for event in supplied}) != len(supplied):
        raise ValidationError("provenance event IDs must be unique")
    nodes: dict[str, ProvenanceNode] = {}
    edges: set[tuple[str, str, str]] = set()
    for event in sorted(supplied, key=lambda item: item.event_id):
        event_id = f"event:{event.event_id}"
        claim_id = f"claim:{event.claim}"
        source_id = f"source:{event.source}"
        nodes.setdefault(claim_id, ProvenanceNode(claim_id, "claim", event.claim))
        nodes.setdefault(source_id, ProvenanceNode(source_id, "source", event.source))
        nodes[event_id] = ProvenanceNode(event_id, "event", event.event_id)
        edges.add(
            (event_id, claim_id, "supports" if event.signal.value == "support" else "contradicts")
        )
        edges.add((source_id, event_id, "produced"))
        if event.correlation_group is not None:
            group_id = f"correlation:{event.correlation_group}"
            nodes.setdefault(
                group_id, ProvenanceNode(group_id, "correlation", event.correlation_group)
            )
            edges.add((group_id, event_id, "groups"))
    return ProvenanceGraph(
        nodes=tuple(sorted(nodes.values(), key=lambda node: (node.kind, node.id))),
        edges=tuple(
            ProvenanceEdge(source, target, relation) for source, target, relation in sorted(edges)
        ),
    )


__all__ = ["NodeKind", "ProvenanceEdge", "ProvenanceGraph", "ProvenanceNode", "build_provenance"]
