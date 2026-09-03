"""Command-line interface for fixed-time evaluation and historical replay."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .engine import evaluate
from .errors import EvidenceBraidError, InputFormatError
from .io import canonical_json, load_events, load_policy, write_text
from .models import parse_timestamp
from .replay import replay
from .report import render_html, render_svg


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

    replay_parser = subparsers.add_parser("replay", help="evaluate after each ingestion timestamp")
    replay_parser.add_argument("policy", type=Path, help="policy JSON file")
    replay_parser.add_argument("events", type=Path, help="evidence JSONL file")
    replay_parser.add_argument(
        "--output", default="-", help="result JSONL destination, or - for stdout"
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


def run(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        events = load_events(args.events)
        if args.command == "evaluate":
            as_of = parse_timestamp(args.as_of, "--as-of")
            result = evaluate(policy, events, as_of)
            _emit(args.output, canonical_json(result.to_dict()))
            if args.html:
                write_text(args.html, render_html(result))
            if args.svg:
                write_text(args.svg, render_svg(result))
        else:
            results = replay(policy, events)
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
