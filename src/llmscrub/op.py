"""Fetch concealed secret values from 1Password for literal-string matching."""
from __future__ import annotations
import json, shutil, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from .extra import shannon


_PASSWORD_CATEGORIES = {"LOGIN", "PASSWORD", "DATABASE", "SECURE_NOTE", "API_CREDENTIAL"}


def _plausible_secret(val: str, min_len: int) -> bool:
    """Drop values that look like names/dictionary words rather than real secrets.
    Short values must have non-trivial entropy; long values pass regardless."""
    if len(val) < min_len or val.isdigit():
        return False
    if len(val) < 16 and shannon(val) < 3.0:
        return False
    return True


def _op_account() -> list[str]:
    """Return ['--account', url] for the first signed-in account, or []."""
    try:
        proc = subprocess.run(
            ["op", "account", "list", "--format", "json"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        accounts = json.loads(proc.stdout)
        if accounts:
            return ["--account", accounts[0]["url"]]
    except Exception:
        pass
    return []


def _get_item(item_id: str, account: list[str]) -> dict | None:
    try:
        proc = subprocess.run(
            ["op", "item", "get", item_id, "--format", "json", "--reveal"] + account,
            capture_output=True, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return json.loads(proc.stdout)
    except Exception:
        return None


def fetch_secrets(min_len: int = 8, workers: int = 15) -> list[str]:
    """Return all concealed field values from 1Password. Empty list if op unavailable."""
    if not shutil.which("op"):
        return []
    account = _op_account()
    try:
        proc = subprocess.run(
            ["op", "item", "list", "--format", "json"] + account,
            capture_output=True, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        all_items = json.loads(proc.stdout)
    except Exception:
        return []

    ids = [
        item["id"] for item in all_items
        if item.get("category") in _PASSWORD_CATEGORIES and "id" in item
    ]

    secrets: list[str] = []
    seen: set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_get_item, id_, account): id_ for id_ in ids}
        for future in as_completed(futures):
            item = future.result()
            if not item:
                continue
            for field in item.get("fields", []):
                if field.get("type") != "CONCEALED":
                    continue
                val = field.get("value", "")
                if val and val not in seen and _plausible_secret(val, min_len):
                    seen.add(val)
                    secrets.append(val)

    return secrets
