"""Dependency-free human-readable HTML and SVG reports."""

from __future__ import annotations

from html import escape

from .engine import ClaimDecision, EvaluationResult
from .models import Outcome, format_timestamp

_OUTCOME_COLOR = {
    Outcome.ESCALATE: "#b42318",
    Outcome.REJECT: "#067647",
    Outcome.REVIEW: "#b54708",
}


def _score_bar(label: str, value: float, color: str) -> str:
    percentage = min(max(value * 100.0, 0.0), 100.0)
    return f"""
      <div class="score-row">
        <span>{escape(label)}</span>
        <div class="bar"><i style="width:{percentage:.2f}%;background:{color}"></i></div>
        <strong>{value:.3f}</strong>
      </div>"""


def _decision_section(decision: ClaimDecision) -> str:
    color = _OUTCOME_COLOR[decision.outcome]
    trace_rows = []
    for event in decision.trace:
        trace_rows.append(
            "<tr>"
            f"<td><code>{escape(event.event_id)}</code></td>"
            f"<td>{escape(event.modality)}</td>"
            f"<td>{escape(event.source)}</td>"
            f"<td>{escape(event.signal)}</td>"
            f"<td>{event.raw_confidence:.3f}</td>"
            f"<td>{event.decay_factor:.3f}</td>"
            f"<td>{event.effective_confidence:.3f}</td>"
            "</tr>"
        )
    rows = "".join(trace_rows) or '<tr><td colspan="7" class="empty">No evidence</td></tr>'
    return f"""
    <section class="decision">
      <div class="decision-head">
        <div><p class="eyebrow">Claim</p><h2>{escape(decision.claim)}</h2></div>
        <span class="badge" style="background:{color}">{decision.outcome.value.upper()}</span>
      </div>
      <p class="reason">{escape(decision.reason.replace("_", " "))}</p>
      {_score_bar("Support", decision.support.score, "#2563eb")}
      {_score_bar("Contradict", decision.contradict.score, "#7c3aed")}
      <dl>
        <div><dt>Margin</dt><dd>{decision.margin:.3f}</dd></div>
        <div><dt>Support groups</dt><dd>{decision.support.qualifying_groups}</dd></div>
        <div><dt>Sources</dt><dd>{len(decision.support.qualifying_sources)}</dd></div>
        <div><dt>Modalities</dt><dd>{len(decision.support.qualifying_modalities)}</dd></div>
      </dl>
      <details><summary>Decision trace ({len(decision.trace)} events)</summary>
        <div class="table-wrap"><table><thead><tr><th>Event</th><th>Modality</th><th>Source</th>
        <th>Signal</th><th>Raw</th><th>Decay</th><th>Effective</th></tr></thead>
        <tbody>{rows}</tbody></table></div>
      </details>
    </section>"""


def _reliability_section(result: EvaluationResult) -> str:
    """Show any reliability the caller's ground truth moved, or nothing at all."""
    updates = result.reliability_updates
    if not updates:
        return ""
    rows = "".join(
        "<tr>"
        f"<td><code>{escape(item.source)}</code></td>"
        f"<td>{item.declared_reliability:.3f}</td>"
        f"<td>{item.correct_count}</td>"
        f"<td>{item.incorrect_count}</td>"
        f"<td>{item.applied_reliability:.3f}</td>"
        f"<td>{item.adjustment:+.3f}</td>"
        "</tr>"
        for item in updates
    )
    return f"""
    <section class="decision">
      <div class="decision-head"><div><p class="eyebrow">Sources</p>
        <h2>Reliability updates</h2></div></div>
      <p class="reason">Applied from caller-supplied adjudications. Machine JSON lists the adjudicated event IDs.</p>
      <div class="table-wrap"><table><thead><tr><th>Source</th><th>Declared</th><th>Correct</th>
      <th>Incorrect</th><th>Applied</th><th>Change</th></tr></thead>
      <tbody>{rows}</tbody></table></div>
    </section>"""


def render_html(result: EvaluationResult) -> str:
    """Render a standalone HTML file without network assets or scripts."""
    sections = "".join(_decision_section(decision) for decision in result.decisions)
    sections += _reliability_section(result)
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Evidence Braid report · {escape(result.policy_id)}</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color:#172033; }}
    * {{ box-sizing:border-box }}
    body {{ margin:0; background:#f4f6fa; }}
    main {{ width:min(1060px, calc(100% - 32px)); margin:48px auto 80px; }}
    header {{ padding:28px 32px; color:white; border-radius:18px; background:linear-gradient(120deg,#172554,#312e81); }}
    header p {{ color:#dbeafe; margin:8px 0 0; }}
    h1,h2,p {{ margin-top:0 }} h1 {{ margin-bottom:0; letter-spacing:-.03em }} h2 {{ margin-bottom:0 }}
    .meta {{ display:flex; gap:24px; flex-wrap:wrap; margin-top:24px; font-size:.9rem }}
    .decision {{ margin-top:20px; padding:28px 32px; border:1px solid #e2e8f0; border-radius:18px; background:white; box-shadow:0 6px 24px #1725540c; }}
    .decision-head {{ display:flex; align-items:center; justify-content:space-between; gap:16px }}
    .eyebrow {{ margin:0 0 5px; color:#64748b; font-size:.76rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase }}
    .badge {{ color:white; border-radius:999px; padding:7px 12px; font-size:.76rem; font-weight:800; letter-spacing:.06em }}
    .reason {{ color:#64748b; margin:10px 0 22px }}
    .score-row {{ display:grid; grid-template-columns:92px 1fr 60px; gap:12px; align-items:center; margin:12px 0 }}
    .bar {{ height:10px; background:#edf2f7; overflow:hidden; border-radius:99px }} .bar i {{ display:block; height:100%; border-radius:99px }}
    dl {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:24px 0 }} dl div {{ padding:12px; background:#f8fafc; border-radius:10px }}
    dt {{ color:#64748b; font-size:.78rem }} dd {{ margin:4px 0 0; font-weight:750 }}
    details {{ border-top:1px solid #e2e8f0; padding-top:18px }} summary {{ cursor:pointer; font-weight:700 }}
    .table-wrap {{ overflow:auto; margin-top:14px }} table {{ width:100%; border-collapse:collapse; font-size:.84rem }}
    th,td {{ text-align:left; padding:9px; border-bottom:1px solid #e2e8f0 }} th {{ color:#475569 }} .empty {{ text-align:center;color:#64748b }}
    footer {{ text-align:center; color:#64748b; margin-top:24px; font-size:.82rem }}
    @media(max-width:680px) {{ dl {{ grid-template-columns:1fr 1fr }} .decision,header {{ padding:22px }} }}
  </style>
</head>
<body><main>
  <header><h1>Evidence Braid</h1><p>Deterministic decision report</p>
    <div class="meta"><span>Policy <strong>{escape(result.policy_id)}</strong></span>
      <span>Evaluated <strong>{format_timestamp(result.evaluated_at)}</strong></span>
      <span>Evidence <strong>{result.considered_event_count}/{result.input_event_count}</strong></span></div>
  </header>
  {sections}
  <footer>Digest: <code>{result.digest}</code></footer>
</main></body></html>
"""
    return "\n".join(line.rstrip() for line in document.splitlines()) + "\n"


def render_svg(result: EvaluationResult) -> str:
    """Render a compact static outcome card used by the README demo."""
    width = 920
    row_height = 88
    height = 124 + row_height * len(result.decisions)
    rows: list[str] = []
    for index, decision in enumerate(result.decisions):
        y = 94 + index * row_height
        color = _OUTCOME_COLOR[decision.outcome]
        support_width = decision.support.score * 250
        contradict_width = decision.contradict.score * 250
        rows.append(
            f'<text x="36" y="{y + 24}" class="claim">{escape(decision.claim)}</text>'
            f'<rect x="314" y="{y}" width="250" height="12" rx="6" fill="#dbeafe"/>'
            f'<rect x="314" y="{y}" width="{support_width:.2f}" height="12" rx="6" fill="#2563eb"/>'
            f'<text x="574" y="{y + 11}" class="score">{decision.support.score:.3f} support</text>'
            f'<rect x="314" y="{y + 26}" width="250" height="12" rx="6" fill="#ede9fe"/>'
            f'<rect x="314" y="{y + 26}" width="{contradict_width:.2f}" height="12" rx="6" fill="#7c3aed"/>'
            f'<text x="574" y="{y + 37}" class="score">{decision.contradict.score:.3f} contradict</text>'
            f'<rect x="756" y="{y - 5}" width="128" height="32" rx="16" fill="{color}"/>'
            f'<text x="820" y="{y + 16}" text-anchor="middle" class="outcome">{decision.outcome.value.upper()}</text>'
        )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">Evidence Braid decision summary</title>
  <desc id="desc">Outcome scores generated from the checked-in example</desc>
  <style>.title{{font:700 25px system-ui;fill:#fff}}.sub{{font:14px system-ui;fill:#bfdbfe}}.claim{{font:650 16px system-ui;fill:#172033}}.score{{font:12px system-ui;fill:#475569}}.outcome{{font:750 12px system-ui;fill:#fff;letter-spacing:.5px}}</style>
  <rect width="920" height="{height}" rx="18" fill="#f8fafc"/>
  <path d="M18 0h884a18 18 0 0 1 18 18v48H0V18A18 18 0 0 1 18 0" fill="#172554"/>
  <text x="30" y="34" class="title">Evidence Braid</text><text x="30" y="54" class="sub">{escape(result.policy_id)} · {format_timestamp(result.evaluated_at)}</text>
  {"".join(rows)}
</svg>
"""
