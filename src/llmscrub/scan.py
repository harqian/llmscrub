"""Invoke trufflehog, gitleaks, and the extra scanner. Yield unified findings."""
from __future__ import annotations
import json, subprocess, shutil, tempfile
from pathlib import Path
from typing import Iterator, Tuple

from .extra import scan_paths as scan_extra, Finding


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_trufflehog(roots) -> Iterator[Finding]:
    if not _have("trufflehog"):
        return
    for root in roots:
        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", "--json", str(root)],
                capture_output=True, text=True, check=False,
            )
        except Exception:
            continue
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            raw = obj.get("Raw", "")
            det = obj.get("DetectorName", "")
            if not raw or len(raw) < 8 or not det:
                continue
            try:
                file = obj["SourceMetadata"]["Data"]["Filesystem"]["file"]
            except KeyError:
                continue
            yield (Path(file), det, raw)


def run_gitleaks(roots) -> Iterator[Finding]:
    if not _have("gitleaks"):
        return
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gitleaks.json"
        for root in roots:
            try:
                subprocess.run(
                    ["gitleaks", "detect", "--source", str(root),
                     "--no-git", "-r", str(out), "-f", "json", "--exit-code", "0"],
                    capture_output=True, check=False,
                )
            except Exception:
                continue
            if not out.exists():
                continue
            try:
                data = json.loads(out.read_text())
            except Exception:
                continue
            for leak in data:
                raw = leak.get("Secret", "")
                rule = leak.get("RuleID", "gitleaks")
                file = leak.get("File", "")
                if not raw or len(raw) < 8 or not file:
                    continue
                yield (Path(file), f"gl:{rule}", raw)


def _is_placeholder(raw: str) -> bool:
    """Skip our own placeholder strings if a scanner re-flags them."""
    return "[REDACTED:" in raw


def scan_op_secrets(roots, secrets: list[str]) -> Iterator[Finding]:
    """Exact-string scan for known 1Password secret values."""
    if not secrets:
        return
    for root in roots:
        p = Path(root)
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
        for f in files:
            try:
                text = f.read_text(errors="replace")
            except Exception:
                continue
            for val in secrets:
                if val in text:
                    yield (f, "1Password", val)


def scan_all(roots, *, use_trufflehog=True, use_gitleaks=True, use_extras=True,
             op_secrets: "list[str] | None" = None) -> Iterator[Finding]:
    """Run every available scanner. Caller dedupes."""
    def _filter(it):
        for path, det, raw in it:
            if not _is_placeholder(raw):
                yield path, det, raw

    if use_trufflehog:
        yield from _filter(run_trufflehog(roots))
    if use_gitleaks:
        yield from _filter(run_gitleaks(roots))
    if use_extras:
        yield from _filter(scan_extra(roots))
    if op_secrets:
        yield from _filter(scan_op_secrets(roots, op_secrets))
