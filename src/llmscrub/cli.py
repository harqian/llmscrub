"""Command-line entry point."""
from __future__ import annotations
import argparse, datetime, os, sys
from collections import Counter
from pathlib import Path

from . import __version__
from .scan import scan_all
from .redact import apply

DEFAULT_TARGETS = [
    "~/.claude/projects",
    "~/.codex",
]


def _expand(paths):
    return [Path(os.path.expanduser(p)) for p in paths]


def cmd_scan(args):
    roots = _expand(args.path or DEFAULT_TARGETS)
    roots = [r for r in roots if r.exists()]
    if not roots:
        print("no target paths exist", file=sys.stderr)
        return 1

    seen = set()
    by_det = Counter()
    by_file = Counter()
    for path, det, raw in scan_all(roots):
        key = (str(path), det, raw)
        if key in seen:
            continue
        seen.add(key)
        by_det[det] += 1
        by_file[str(path)] += 1

    print(f"unique findings: {len(seen)}")
    print(f"files affected:  {len(by_file)}")
    print("by detector:")
    for d, n in by_det.most_common():
        print(f"  {d:30s} {n}")
    if args.verbose:
        print("\nby file:")
        for f, n in by_file.most_common(20):
            print(f"  {n:4d}  {f}")
    return 0


def cmd_redact(args):
    roots = _expand(args.path or DEFAULT_TARGETS)
    roots = [r for r in roots if r.exists()]
    if not roots:
        print("no target paths exist", file=sys.stderr)
        return 1

    backup = None
    if args.backup:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = Path(os.path.expanduser(args.backup)) / ts
        backup.mkdir(parents=True, exist_ok=True)
        print(f"backup: {backup}")

    total = Counter()
    for round_n in range(1, args.max_rounds + 1):
        print(f"\n== round {round_n} ==")
        findings = list(scan_all(roots))
        # dedupe by (file, raw) — detector doesn't matter for redaction
        unique = {}
        for path, det, raw in findings:
            k = (str(path), raw)
            if k not in unique:
                unique[k] = (path, det, raw)
        if not unique:
            print("no findings — done")
            break
        print(f"findings: {len(findings)} / unique: {len(unique)}")
        if args.dry_run:
            # show summary once
            det_ct = Counter(d for _, d, _ in unique.values())
            for d, n in det_ct.most_common():
                print(f"  {d:30s} {n}")
            break
        summary = apply(unique.values(), backup_dir=backup, dry_run=False)
        total["files"] += summary["files"]
        total["subs"] += summary["subs"]
        total["failed"] += len(summary["failed"])
        print(f"files: {summary['files']}  subs: {summary['subs']}  failed: {len(summary['failed'])}")
        if summary["failed"]:
            for f, err in summary["failed"]:
                print(f"  FAIL {f}: {err}", file=sys.stderr)
        if summary["files"] == 0:
            break
    else:
        print(f"\nreached max rounds ({args.max_rounds})")

    print(f"\ntotal files: {total['files']}  total subs: {total['subs']}")
    return 0 if total["failed"] == 0 else 2


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="llmscrub",
        description="Sweep LLM agent logs (Claude Code, Codex) for leaked secrets and redact them."
    )
    p.add_argument("--version", action="version", version=f"llmscrub {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="report secrets found in logs (no modification)")
    s.add_argument("path", nargs="*", help=f"paths to scan (default: {' '.join(DEFAULT_TARGETS)})")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redact", help="redact secrets in place (creates backup)")
    r.add_argument("path", nargs="*")
    r.add_argument("--backup", default="~/.llmscrub/backups",
                   help="backup directory (default: ~/.llmscrub/backups; set to empty to disable)")
    r.add_argument("--dry-run", action="store_true", help="report without modifying")
    r.add_argument("--max-rounds", type=int, default=3,
                   help="max scan-redact iterations (default: 3)")
    r.set_defaults(func=cmd_redact)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
