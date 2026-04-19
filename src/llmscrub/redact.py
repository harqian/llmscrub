"""Apply redactions in-place with backup + JSONL validation."""
from __future__ import annotations
import hashlib, json, shutil
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Tuple

Finding = Tuple[Path, str, str]


def placeholder(raw: str, det: str) -> str:
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"[REDACTED:{det}:{h}]"


def validate_jsonl(path: Path) -> tuple[bool, str | None]:
    if not str(path).endswith(".jsonl"):
        return True, None
    try:
        with path.open() as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if line:
                    json.loads(line)
        return True, None
    except Exception as e:
        return False, f"line {i}: {e}"


def apply(findings: Iterable[Finding], *,
          backup_dir: Path | None = None,
          dry_run: bool = False) -> dict:
    by_file: dict[Path, list[tuple[str, str]]] = defaultdict(list)
    for path, det, raw in findings:
        by_file[path].append((raw, det))

    summary = {"files": 0, "subs": 0, "skipped": 0, "failed": []}
    for path, items in by_file.items():
        if not path.exists():
            summary["skipped"] += 1
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            summary["skipped"] += 1
            continue

        subs = 0
        # longest first — avoids PEM block partial-match interfering with embedded content
        for raw, det in sorted(items, key=lambda x: -len(x[0])):
            if not raw:
                continue
            count = text.count(raw)
            if count:
                text = text.replace(raw, placeholder(raw, det))
                subs += count
        if subs == 0:
            continue

        if dry_run:
            summary["files"] += 1
            summary["subs"] += subs
            continue

        if backup_dir:
            rel = path.resolve().relative_to("/")
            bpath = backup_dir / rel
            bpath.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, bpath)
        path.write_text(text)
        ok, err = validate_jsonl(path)
        if not ok:
            summary["failed"].append((str(path), err))
            if backup_dir:
                shutil.copy2(bpath, path)  # rollback
            continue
        summary["files"] += 1
        summary["subs"] += subs

    return summary
