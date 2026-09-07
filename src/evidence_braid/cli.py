"""Command-line interface for fixed-time evaluation and historical replay."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .comparison import compare_policies, decision_impact
from .engine import evaluate
from .errors import EvidenceBraidError, InputFormatError
from .io import (
    canonical_json,
    load_adjudications,
    load_events,
    load_json,
    load_policy,
    write_text,
)
from .migrations import CURRENT_POLICY_SCHEMA_VERSION, migrate_policy_document
from .models import Policy, parse_timestamp
from .replay import replay
from .report import render_html, render_svg
from .robustness import robustness
from .storage import MAX_LEDGER_BYTES, SQLiteLedger, load_ledger


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-braid",
        description="Evaluate multimodal evidence with a deterministic JSON policy.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate all evidence at one instant")
    evaluate_parser.add_argument("policy", type=Path, help="policy JSON file")
    evaluate_parser.add_argument("events", type=Path, help="evidence JSONL file")
    evaluate_parser.add_argument("--as-of", required=True, help="timezone-aware ISO-8601 instant")
    evaluate_parser.add_argument(
        "--output", default="-", help="machine JSON destination, or - for stdout"
    )
    evaluate_parser.add_argument("--html", help="optional standalone HTML report destination")
    evaluate_parser.add_argument("--svg", help="optional SVG summary destination")
    evaluate_parser.add_argument(
        "--adjudications", type=Path, help="optional adjudicated-outcome JSONL file"
    )

    replay_parser = subparsers.add_parser("replay", help="evaluate after each ingestion timestamp")
    replay_parser.add_argument("policy", type=Path, help="policy JSON file")
    replay_parser.add_argument("events", type=Path, help="evidence JSONL file")
    replay_parser.add_argument(
        "--output", default="-", help="result JSONL destination, or - for stdout"
    )
    replay_parser.add_argument(
        "--adjudications", type=Path, help="optional adjudicated-outcome JSONL file"
    )

    robustness_parser = subparsers.add_parser(
        "robustness", help="measure claim outcome dependence on one visible event"
    )
    robustness_parser.add_argument("policy", type=Path, help="policy JSON file")
    robustness_parser.add_argument("events", type=Path, help="evidence JSONL file")
    robustness_parser.add_argument("--as-of", required=True, help="timezone-aware ISO-8601 instant")
    robustness_parser.add_argument(
        "--max-events",
        type=int,
        default=256,
        help="maximum visible events to perturb (default: 256)",
    )
    robustness_parser.add_argument(
        "--output", default="-", help="machine JSON destination, or - for stdout"
    )
    robustness_parser.add_argument(
        "--adjudications", type=Path, help="optional adjudicated-outcome JSONL file"
    )

    migrate_parser = subparsers.add_parser(
        "migrate-policy",
        help=f"upgrade a policy document to schema {CURRENT_POLICY_SCHEMA_VERSION}",
    )
    migrate_parser.add_argument("policy", type=Path, help="policy JSON file")
    migrate_parser.add_argument(
        "--output", default="-", help="upgraded policy destination, or - for stdout"
    )
    migrate_parser.add_argument(
        "--report", help="optional JSON destination for the list of changes"
    )

    diff_parser = subparsers.add_parser(
        "diff-policy", help="explain how two policies differ, and what that changes"
    )
    diff_parser.add_argument("before", type=Path, help="the policy in use")
    diff_parser.add_argument("after", type=Path, help="the policy being considered")
    diff_parser.add_argument(
        "--output", default="-", help="comparison JSON destination, or - for stdout"
    )
    diff_parser.add_argument(
        "--events", type=Path, help="optional evidence JSONL, to report which decisions move"
    )
    diff_parser.add_argument(
        "--as-of", help="timezone-aware ISO-8601 instant, required with --events"
    )
    diff_parser.add_argument(
        "--adjudications", type=Path, help="optional adjudicated-outcome JSONL"
    )
    ledger_parser = subparsers.add_parser(
        "ledger", help="append, verify, export, or import a durable evidence ledger"
    )
    ledger_commands = ledger_parser.add_subparsers(dest="ledger_command", required=True)
    for command in ("append", "verify", "export", "import"):
        operation = ledger_commands.add_parser(command)
        operation.add_argument("database", type=Path, help="local SQLite ledger file")
        if command in ("append", "import"):
            operation.add_argument(
                "source", type=Path, help="event JSONL (append) or ledger JSON (import)"
            )
        operation.add_argument("--output", default="-", help="JSON destination, or - for stdout")
        operation.add_argument(
            "--expected-head", help="independently retained SHA-256 head to compare"
        )
    return parser


def _emit(destination: str, content: str) -> None:
    if destination == "-":
        try:
            sys.stdout.write(content)
        except UnicodeError as exc:
            raise InputFormatError(f"cannot encode output for stdout: {exc}") from exc
    else:
        write_text(destination, content)


def _emit_error(error: EvidenceBraidError) -> None:
    message = f"error: {error}"
    message = "".join(
        character if character.isprintable() else ascii(character)[1:-1] for character in message
    )
    encoding = getattr(sys.stderr, "encoding", None)
    if encoding:
        try:
            message.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            message = message.encode("ascii", "backslashreplace").decode("ascii")
    try:
        sys.stderr.write(f"{message}\n")
    except UnicodeEncodeError:
        escaped = message.encode("ascii", "backslashreplace").decode("ascii")
        sys.stderr.write(f"{escaped}\n")


def _migrate_policy(args: argparse.Namespace) -> None:
    """Rewrite one policy document at the current schema and report the changes.

    The upgraded document is validated before it is written, so this never emits
    a file that ``load_policy`` would then refuse.
    """

    document, report = migrate_policy_document(load_json(args.policy))
    Policy.from_dict(document)
    _emit(args.output, canonical_json(document))
    if args.report:
        write_text(args.report, canonical_json(report.to_dict()))


def _diff_policy(args: argparse.Namespace) -> None:
    """Compare two policies, and optionally show which decisions move.

    The field comparison says which gates changed and in which direction. It
    cannot say whether any claim was near those gates, so `--events` runs both
    policies over the same evidence at one instant and reports the outcomes that
    actually differ. Neither answer replaces the other.
    """

    before = load_policy(args.before)
    after = load_policy(args.after)
    payload: dict[str, object] = {
        # Reported with forward slashes so the same comparison produces the
        # same document on either platform.
        "before": args.before.as_posix(),
        "after": args.after.as_posix(),
        "comparison": compare_policies(before, after).to_dict(),
    }
    if args.events is not None:
        if not args.as_of:
            raise InputFormatError("--events requires --as-of")
        as_of = parse_timestamp(args.as_of, "--as-of")
        events = load_events(args.events)
        adjudications = load_adjudications(args.adjudications) if args.adjudications else []
        payload["decision_impact"] = decision_impact(
            before, after, events, as_of, adjudications=adjudications
        ).to_dict()
    elif args.as_of:
        raise InputFormatError("--as-of has no effect without --events")
    _emit(args.output, canonical_json(payload))


def _ledger(args: argparse.Namespace) -> None:
    if args.output != "-":
        output = Path(args.output)
        if output.resolve() == args.database.resolve() or (
            output.exists() and args.database.exists() and output.samefile(args.database)
        ):
            raise InputFormatError("ledger output must not overwrite its database")
    if args.ledger_command == "import":
        imported = load_ledger(args.source, expected_head=args.expected_head)
        result = SQLiteLedger(args.database).import_snapshot(imported)
    elif args.ledger_command == "append":
        events = load_events(args.source)
        result = SQLiteLedger(args.database).append(events, expected_head=args.expected_head)
    else:
        result = SQLiteLedger(args.database, create=False).snapshot(
            expected_head=args.expected_head
        )
    payload = (
        result.to_dict()
        if args.ledger_command == "export"
        else {
            "schema_version": result.schema_version,
            "entry_count": len(result.entries),
            "head_digest": result.head_digest,
            "verified": True,
        }
    )
    content = canonical_json(payload, pretty=False) + "\n"
    if len(content.encode("utf-8")) > MAX_LEDGER_BYTES:
        raise InputFormatError("ledger output exceeds the 64 MiB limit")
    _emit(args.output, content)


def run(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "ledger":
            _ledger(args)
            return 0
        if args.command == "migrate-policy":
            _migrate_policy(args)
            return 0
        if args.command == "diff-policy":
            _diff_policy(args)
            return 0
        policy = load_policy(args.policy)
        events = load_events(args.events)
        adjudications = load_adjudications(args.adjudications) if args.adjudications else []
        if args.command == "evaluate":
            as_of = parse_timestamp(args.as_of, "--as-of")
            result = evaluate(policy, events, as_of, adjudications=adjudications)
            _emit(args.output, canonical_json(result.to_dict()))
            if args.html:
                write_text(args.html, render_html(result))
            if args.svg:
                write_text(args.svg, render_svg(result))
        elif args.command == "robustness":
            as_of = parse_timestamp(args.as_of, "--as-of")
            report = robustness(
                policy,
                events,
                as_of,
                adjudications=adjudications,
                max_events=args.max_events,
            )
            _emit(args.output, canonical_json(report.to_dict()))
        else:
            results = replay(policy, events, adjudications=adjudications)
            content = "".join(
                canonical_json(result.to_dict(), pretty=False) + "\n" for result in results
            )
            _emit(args.output, content)
    except EvidenceBraidError as exc:
        _emit_error(exc)
        return 2
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
