"""Secret patterns beyond trufflehog/gitleaks: PEM blocks, env-var assignments,
Bearer/Basic auth, URL-with-embedded-password.
"""
from __future__ import annotations
import base64, math, re
from collections import Counter
from pathlib import Path
from typing import Iterator, Tuple

Finding = Tuple[Path, str, str]  # (file, detector, raw)

PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"(?:.|\\n|\n){10,8000}?"
    r"-----END [A-Z ]*PRIVATE KEY-----"
)
ENV_ASSIGN = re.compile(
    r'\b([A-Z][A-Z0-9_]{2,})\s*=\s*[\'"]?'
    r'([A-Za-z0-9+/=_\-\.]{20,512})'
    r'[\'"]?(?=\s|$|\\n|\\"|,|;)'
)
EXPORT_ASSIGN = re.compile(
    r'\bexport\s+([A-Z][A-Z0-9_]{2,})\s*=\s*[\'"]?'
    r'([A-Za-z0-9+/=_\-\.]{20,512})'
    r'[\'"]?'
)
BEARER = re.compile(r'[Bb]earer\s+([A-Za-z0-9+/=_\-\.]{20,500})')
BASIC = re.compile(r'[Bb]asic\s+([A-Za-z0-9+/=]{16,500})')
URL_PASS = re.compile(r'([a-z][a-z0-9+.\-]*://[^\s:/@]+):([^\s@/\'"]{6,150})@')
ENV_WRITE_HINT = re.compile(
    r'(?:cat\s*>\s*\.?env\b|\.env(?:\.\w+)?\b|filePath["\']?\s*:\s*["\'][^"\']*\.env)'
)
SENSITIVE_KEY = re.compile(
    r'(?i)(token|secret|api[_-]?key|apikey|password|passwd|'
    r'auth|credential|private[_-]?key|access[_-]?key|client[_-]?secret|'
    r'bearer|session|cookie|jwt|dsn|conn(?:ection)?[_-]?string|'
    r'database[_-]?url|db[_-]?url|redis[_-]?url|mongo[_-]?url|'
    r'webhook|sentry[_-]?dsn)'
)
PLACEHOLDER = re.compile(
    r'^(your[_-].*|example[_-].*|xxxx+|\$\{.*\}|<.*>|undefined|null|true|false|'
    r'REDACTED|placeholder|changeme|password|secret|token|key|'
    r'https?|localhost|127\.0\.0\.1|0\.0\.0\.0)$',
    re.IGNORECASE
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def looks_secret(v: str, min_entropy: float = 3.0) -> bool:
    if len(v) < 16 or PLACEHOLDER.match(v):
        return False
    if shannon(v) < min_entropy:
        return False
    if v.isdigit():
        return False
    return True


def scan_text(path: Path, text: str) -> Iterator[Finding]:
    seen: set[str] = set()

    def maybe(raw: str, det: str, min_e: float = 3.0):
        if raw in seen or not looks_secret(raw, min_e):
            return
        seen.add(raw)

    # PEM blocks — emit always, even below entropy threshold
    for m in PEM_RE.finditer(text):
        raw = m.group(0)
        if raw not in seen:
            seen.add(raw)
            yield (path, "PrivateKey", raw)

    env_context = bool(ENV_WRITE_HINT.search(text))

    for m in ENV_ASSIGN.finditer(text):
        key, val = m.group(1), m.group(2)
        if val in seen or not looks_secret(val):
            continue
        if SENSITIVE_KEY.search(key):
            seen.add(val)
            yield (path, "EnvAssign", val)
        elif env_context and looks_secret(val, 3.5):
            seen.add(val)
            yield (path, "EnvFileValue", val)

    for m in EXPORT_ASSIGN.finditer(text):
        key, val = m.group(1), m.group(2)
        if val in seen or not looks_secret(val):
            continue
        if SENSITIVE_KEY.search(key) or env_context:
            seen.add(val)
            yield (path, "ExportAssign", val)

    for m in BEARER.finditer(text):
        v = m.group(1)
        if v in seen or not looks_secret(v):
            continue
        seen.add(v)
        yield (path, "BearerToken", v)

    for m in URL_PASS.finditer(text):
        v = m.group(2)
        if v in seen or not looks_secret(v):
            continue
        seen.add(v)
        yield (path, "UrlPassword", v)

    for m in BASIC.finditer(text):
        v = m.group(1)
        if v in seen:
            continue
        try:
            if ':' in base64.b64decode(v + '==', validate=False).decode(errors='replace'):
                if looks_secret(v):
                    seen.add(v)
                    yield (path, "BasicAuth", v)
        except Exception:
            pass


def scan_paths(roots) -> Iterator[Finding]:
    for root in roots:
        p = Path(root)
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
        for f in files:
            try:
                text = f.read_text(errors="replace")
            except Exception:
                continue
            yield from scan_text(f, text)
