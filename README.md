# llmscrub

Sweep LLM agent logs (Claude Code, Codex) for leaked secrets and redact them in place.

LLM agents accumulate surprising amounts of secret material in their logs: API keys pasted into prompts, `.env` files read into tool results, `curl -H "Authorization: Bearer ..."` commands, Supabase access tokens baked into MCP config, GCP service-account private keys from `cat credentials.json`, 1Password outputs that got piped to stdout. `llmscrub` stacks several detectors to find them and redacts in place with backups.

## What it detects

Three layers, all run on every invocation:

1. **[trufflehog](https://github.com/trufflesecurity/trufflehog)** — ~700 known-format detectors, many verified against live APIs
2. **[gitleaks](https://github.com/gitleaks/gitleaks)** — regex-heavy ruleset, complementary to trufflehog (catches things like `curl -u user:pass` auth)
3. **Built-in extras** that trufflehog/gitleaks miss:
   - PEM private-key blocks (including embedded in JSONL as `\n`-escaped strings)
   - Environment-variable assignments with sensitive key names (`API_KEY=...`, `DATABASE_URL=...`)
   - `Authorization: Bearer <token>` and `Basic <b64>` headers
   - URL-embedded passwords (`scheme://user:pass@host`)
   - Aggressive `KEY=VAL` redaction when the file context suggests a `.env` write

## What it scans by default

- `~/.claude/projects/` — Claude Code's per-project JSONL session logs
- `~/.codex/` — Codex sessions, TUI logs, shell snapshots

Override with positional paths: `llmscrub scan /path/to/logs`.

## Install

```bash
brew install harqian/tap/llmscrub
```

This pulls in `trufflehog` and `gitleaks` as dependencies.

Manual:
```bash
pip install llmscrub
brew install trufflehog gitleaks
```

## Usage

```bash
llmscrub scan                  # report what's there (read-only)
llmscrub scan -v               # also list affected files

llmscrub redact --dry-run      # preview redactions
llmscrub redact                # redact in place with backup to ~/.llmscrub/backups/<ts>/
llmscrub redact --backup ""    # disable backup (not recommended)
llmscrub redact --max-rounds 5 # more iterations (default 3)
llmscrub redact --fast         # skip gitleaks (10-20× faster, lower recall)
llmscrub scan --fast           # same for scan
```

### Why iteration?

A single pass isn't always enough. If your diagnostic activity (grep, jq) prints a key to terminal while you're investigating, that output lands in the *current* session's log — and a second pass is needed to catch it. `llmscrub redact` loops until no new findings (capped by `--max-rounds`).

### How redaction looks

```diff
- "access-token=sbp_a6570cf63ad638537a4535fefe4cf2eb5006cd05"
+ "access-token=[REDACTED:SupabaseToken:1324f898]"
```

The 8-char hash in the placeholder is `sha256(raw)[:8]` — collisions across rotated keys are visible, and you can correlate redactions without exposing the secret.

JSONL files are validated after redaction; if validation fails the file is restored from backup.

## Guarantees and non-guarantees

- **We do not guarantee** zero false negatives. Novel-format tokens with no public signature (random 32-char alphanumeric strings used as API keys by some internal service) are undetectable by any scanner without a rule for that format. Our extra detectors catch many such cases via context (key name, URL placement, Bearer header) but some slip through.
- **False positives are acceptable.** We intentionally redact some non-secrets (UUIDs caught by heuristic detectors, high-entropy identifiers). Removing session IDs from logs doesn't harm anything; leaving an API key does.
- **Rotate anything trufflehog flagged as `Verified=true`.** Those keys were actively working against the live API when scanned. Redacting the log doesn't revoke them.

## For agents

Paste-able agent prompts — copy either block and give it to Claude Code, Codex, or any CLI-capable agent.

### One-shot: install, scan, report

```
Install llmscrub and run a secret scan against my Claude Code and Codex logs,
then summarize the findings.

Steps:
1. brew install harqian/tap/llmscrub  (installs trufflehog + gitleaks as deps)
2. llmscrub scan --fast   (fast pass: trufflehog + built-in extras, skips gitleaks)
3. For a thorough pass afterwards: llmscrub scan   (adds gitleaks; slower)
4. Report: total unique findings, breakdown by detector, and any detector named
   with the "gl:" prefix or a trufflehog Verified=true entry — those need key
   rotation, not just redaction.
Do not run `llmscrub redact` in this block — only scan.
```

### Daily cron: redact every night at 2am

```
Set up a launchd agent (macOS) or cron entry that runs llmscrub daily to redact
any newly-leaked secrets in my LLM agent logs.

Steps:
1. Ensure llmscrub is installed: brew install harqian/tap/llmscrub
2. On macOS, create ~/Library/LaunchAgents/com.harqian.llmscrub.plist with a
   daily schedule (2am), command: /opt/homebrew/bin/llmscrub redact, stdout/
   stderr to ~/.llmscrub/cron.log. Load it with: launchctl load <path>.
3. On Linux, add to crontab -e:
     0 2 * * * /usr/local/bin/llmscrub redact >> ~/.llmscrub/cron.log 2>&1
4. Verify the job by running llmscrub redact --dry-run once by hand first, then
   tail -f ~/.llmscrub/cron.log after the next scheduled run.
Backups land in ~/.llmscrub/backups/<timestamp>/ — mention to the user they may
want a cleanup policy (e.g. keep last 7 days) once they're comfortable with the
tool.
```

## Limitations

- Screenshots, PDFs, and binary files are not scanned for visible tokens
- MCP server logs outside `~/.claude` and `~/.codex` require explicit paths
- `1password` (`op`) command outputs are only caught if the resulting secret matches a known format — a plain-text password piped to stdout and never repeated is hard to identify structurally

## License

MIT
