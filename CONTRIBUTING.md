# Contributing

Thank you for helping improve Evidence Braid.

## Before opening a change

For bug fixes, open an issue with a minimal policy, event stream, evaluation
time, observed result, and expected result. For policy semantics or public
schema changes, discuss the behavior before implementation because small
changes can alter audited decisions.

Do not include private recordings, operational credentials, personal data, or
evidence you are not authorized to publish.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Run the complete local gate:

```bash
ruff check .
ruff format --check .
pytest --cov=evidence_braid --cov-report=term-missing
python experiments/synthetic_baselines.py --samples 12 --repeats 3 --replay-events 8
```

## Change requirements

- Preserve deterministic behavior across input order.
- Add meaningful tests for normal, boundary, and invalid cases.
- Keep the core dependency-free unless a dependency has a documented need.
- Reject ambiguous input instead of silently coercing it.
- Keep machine output backward compatible within schema version 1.
- Update architecture and README text when semantics change.
- Regenerate example JSON, HTML, and SVG with the documented command.
- Do not claim tests or platforms that were not actually run.
- State dataset provenance and keep generated fixtures labeled synthetic. Labeled evaluations must
  define the label, positive class, abstention treatment, split, baseline, and metric protocol.
- Include Python/OS/CPU, warmup, repeat count, and timing distributions with performance results;
  never present one machine's timing as a universal bound.

Focus pull requests on one concern. Generated artifacts must be accompanied by
the source inputs and the exact generation command.

## Commit and pull request notes

Use concise imperative commit subjects. A pull request should explain the
problem, chosen semantics, alternatives considered, compatibility impact, and
commands actually run. Disclose meaningful tool assistance according to the
policies that apply to your contribution.

By contributing, you agree that your contribution is licensed under the MIT
License included in this repository. All participants must follow the Code of
Conduct.

Project decision authority and release requirements are described in
[`docs/governance.md`](docs/governance.md).
