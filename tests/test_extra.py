from pathlib import Path
from llmscrub.extra import scan_text, shannon, looks_secret

# NOTE: all fixtures below are FAKE. if you need new ones, generate random
# strings — do NOT paste real tokens, even rotated ones. GitHub secret scanning
# and trufflehog will block the push or trigger alerts.
FAKE_TOKEN = "TESTabcdefghijklmnopqrstuvwxyz0123456789"  # 40 chars, high entropy enough


def test_shannon():
    assert shannon("") == 0
    assert shannon("aaaaa") == 0
    assert shannon(FAKE_TOKEN) > 4.0


def test_looks_secret():
    assert not looks_secret("password")
    assert not looks_secret("<token>")
    assert not looks_secret("12345678")
    assert looks_secret(FAKE_TOKEN)


def test_bearer_token():
    text = f'Authorization: Bearer {FAKE_TOKEN}'
    findings = list(scan_text(Path("/tmp/x"), text))
    assert any(d == "BearerToken" for _, d, _ in findings)


def test_url_password():
    text = f'connect to https://admin:{FAKE_TOKEN}@db.example.com/prod'
    findings = list(scan_text(Path("/tmp/x"), text))
    assert any(d == "UrlPassword" for _, d, _ in findings)


def test_env_assign_sensitive_key():
    text = f'API_TOKEN={FAKE_TOKEN}'
    findings = list(scan_text(Path("/tmp/x"), text))
    assert any(d == "EnvAssign" for _, d, _ in findings)


def test_env_assign_non_sensitive_no_context():
    # non-sensitive key name, no env-write context → should not redact
    text = f'BUILD_HASH=abcdefghij0123456789'
    findings = list(scan_text(Path("/tmp/x"), text))
    assert not any(d.startswith("Env") for _, d, _ in findings)


def test_env_file_context_aggressive():
    text = f'''cat > .env <<EOF
RANDOM_KEY={FAKE_TOKEN}
EOF'''
    findings = list(scan_text(Path("/tmp/x"), text))
    assert any(d == "EnvFileValue" for _, d, _ in findings)


def test_pem_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA" + "x" * 100 + "\n-----END RSA PRIVATE KEY-----"
    findings = list(scan_text(Path("/tmp/x"), text))
    assert any(d == "PrivateKey" for _, d, _ in findings)
