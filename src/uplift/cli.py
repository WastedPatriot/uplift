"""Command line for uplift."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from uplift import AUTHORISED_USE, __version__
from uplift.engine import run_assessment
from uplift.host import LiveHost, SnapshotError, load_snapshot
from uplift.models import Report
from uplift.patter import elevator_script
from uplift.report import render_html, render_markdown, render_text
from uplift.score import meets_threshold


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uplift",
        description=("Local privilege-boundary checks for Linux and Windows. " + AUTHORISED_USE),
        epilog="If the car is empty, that is allowed to be the result.",
    )
    parser.add_argument("--version", action="version", version=f"uplift {__version__}")
    parser.add_argument(
        "--os",
        choices=("auto", "linux", "windows"),
        default="auto",
        help="which check set to run (default: auto from the host or snapshot)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the checks and write nothing",
    )
    parser.add_argument(
        "--format",
        choices=("text", "md", "html", "both"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="directory for uplift.txt, uplift.md, or uplift.html",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="JSON host snapshot instead of the live machine",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "low", "medium", "high", "critical"),
        default="high",
        help="exit 2 when a finding reaches this severity (default: high)",
    )
    parser.add_argument(
        "--elevator-music",
        action="store_true",
        help="announce the floors on the way up",
    )
    parser.add_argument(
        "--up",
        action="store_true",
        help="same lift, shorter flag",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.format == "both" and args.output is None and not args.dry_run:
        print("HTML and Markdown together need --output.", file=sys.stderr)
        return 1
    try:
        host = load_snapshot(args.snapshot) if args.snapshot else LiveHost()
    except SnapshotError as exc:
        print(f"uplift: {exc}", file=sys.stderr)
        return 1
    report = run_assessment(host, selected_os=args.os, dry_run=args.dry_run)
    if args.elevator_music or args.up:
        print(
            elevator_script(dry_run=report.dry_run, os_name=report.selected_os, findings=report.findings),
            file=sys.stderr,
        )
    if report.dry_run:
        print(render_text(report), end="")
        return 0
    written = _write(report, args.format, args.output)
    if written:
        print("wrote " + " and ".join(str(path) for path in written))
    elif args.output is None:
        print(_render_stdout(report, args.format), end="")
    return 2 if any(meets_threshold(finding, args.fail_on) for finding in report.findings) else 0


def console() -> None:
    sys.exit(main())


def _render_stdout(report: Report, fmt: str) -> str:
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    return render_text(report)


def _write(report: Report, fmt: str, output: Path | None) -> list[Path]:
    if output is None:
        return []
    output.mkdir(parents=True, exist_ok=True)
    targets: list[tuple[str, str]] = []
    if fmt in {"text", "md", "html"}:
        name = {"text": "uplift.txt", "md": "uplift.md", "html": "uplift.html"}[fmt]
        body = {"text": render_text, "md": render_markdown, "html": render_html}[fmt](report)
        targets.append((name, body))
    else:
        targets.append(("uplift.md", render_markdown(report)))
        targets.append(("uplift.html", render_html(report)))
    written: list[Path] = []
    for name, body in targets:
        path = output / name
        path.write_text(body, encoding="utf-8")
        written.append(path)
    return written
