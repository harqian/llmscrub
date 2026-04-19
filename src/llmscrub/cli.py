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


def _scan_kwargs(args):
    return dict(
        use_trufflehog=not args.no_trufflehog,
        use_gitleaks=not (args.fast or args.no_gitleaks),
        use_extras=not args.no_extras,
    )


def cmd_scan(args):
    roots = _expand(args.path or DEFAULT_TARGETS)
    roots = [r for r in roots if r.exists()]
    if not roots:
        print("no target paths exist", file=sys.stderr)
        return 1

    seen = set()
    by_det = Counter()
    by_file = Counter()
    for path, det, raw in scan_all(roots, **_scan_kwargs(args)):
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


def _filter_recent(findings, skip_recent_secs):
    """Drop findings for files modified in the last N seconds."""
    if skip_recent_secs <= 0:
        yield from findings
        return
    import time
    now = time.time()
    skipped = set()
    for path, det, raw in findings:
        try:
            if now - path.stat().st_mtime < skip_recent_secs:
                skipped.add(str(path))
                continue
        except FileNotFoundError:
            continue
        yield path, det, raw
    if skipped:
        print(f"skipped {len(skipped)} actively-modified file(s) "
              f"(< {skip_recent_secs:g}s old; use --skip-recent 0 to include)",
              file=sys.stderr)


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

    findings = list(_filter_recent(
        scan_all(roots, **_scan_kwargs(args)), args.skip_recent))
    unique = {}
    for path, det, raw in findings:
        k = (str(path), raw)
        if k not in unique:
            unique[k] = (path, det, raw)
    if not unique:
        print("no findings")
        return 0
    print(f"findings: {len(findings)} / unique: {len(unique)}")
    if args.dry_run:
        det_ct = Counter(d for _, d, _ in unique.values())
        for d, n in det_ct.most_common():
            print(f"  {d:30s} {n}")
        return 0
    summary = apply(unique.values(), backup_dir=backup, dry_run=False)
    print(f"files: {summary['files']}  subs: {summary['subs']}  failed: {len(summary['failed'])}")
    if summary["failed"]:
        for f, _err in summary["failed"]:
            # don't echo parser error messages — they may quote file content
            print(f"  FAIL {f}: jsonl validation failed after write, restored from backup",
                  file=sys.stderr)
    return 0 if not summary["failed"] else 2


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="llmscrub",
        description="Sweep LLM agent logs (Claude Code, Codex) for leaked secrets and redact them."
    )
    p.add_argument("--version", action="version", version=f"llmscrub {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_scan_flags(p):
        p.add_argument("--fast", action="store_true",
                       help="skip gitleaks (faster but lower recall; gitleaks is 10-20x slower on large dirs)")
        p.add_argument("--no-trufflehog", action="store_true")
        p.add_argument("--no-gitleaks", action="store_true")
        p.add_argument("--no-extras", action="store_true")

    s = sub.add_parser("scan", help="report secrets found in logs (no modification)")
    s.add_argument("path", nargs="*", help=f"paths to scan (default: {' '.join(DEFAULT_TARGETS)})")
    s.add_argument("-v", "--verbose", action="store_true")
    add_scan_flags(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redact", help="redact secrets in place (creates backup)")
    r.add_argument("path", nargs="*")
    r.add_argument("--backup", default="~/.llmscrub/backups",
                   help="backup directory (default: ~/.llmscrub/backups; set to empty to disable)")
    r.add_argument("--dry-run", action="store_true", help="report without modifying")
    r.add_argument("--skip-recent", type=float, default=10.0,
                   help="skip files modified in the last N seconds (default: 10), "
                        "to avoid racing an actively-written session log. "
                        "set to 0 to include every file.")
    add_scan_flags(r)
    r.set_defaults(func=cmd_redact)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
