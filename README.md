# Daily Threat Intelligence Vault

This private repository is an Obsidian-compatible daily cybersecurity-news vault.
At 06:00 JST, GitHub Actions reads the RSS feeds in `config/sources.yaml`, lets
GitHub Copilot CLI classify and summarize the bounded candidates, and commits a
daily Markdown note to `content/daily/`.

## Current AI integration

GitHub Models is **not** used: GitHub retired its model catalog and inference
API on 2026-07-30. This project instead uses GitHub Copilot CLI from an Actions
workflow, authenticated with its short-lived `GITHUB_TOKEN`. In a personally
owned repository, usage is billed against the repository owner's Copilot seat.
You must have an active Copilot entitlement for the scheduled AI step to work.

The workflow grants only `contents: write` and `copilot-requests: write`. It
does not give Copilot shell, browser, network, SSH, or file-write tools. RSS and
article fetching are deterministic Python steps; Copilot receives only bounded,
untrusted excerpts and returns JSON. Python validates that JSON and builds the
Markdown from a fixed template.

## Initial setup

1. Create a **private** GitHub repository and push this directory to it.
2. Confirm that GitHub Copilot is available on the account that owns the
   repository. The student benefit can provide GitHub Pro, but Copilot access
   must be active separately.
3. In repository **Settings → Actions → General**, allow workflows to have
   read/write permissions if the account policy overrides the workflow's
   `contents: write` permission.
4. In the **Actions** tab, run `Daily threat-intelligence brief` manually once.
   It will create `content/daily/YYYY-MM-DD.md` and `state/brief_state.json`.
5. Clone this private repository as, or inside, the local Obsidian vault. Use
   your preferred Git sync method to pull the daily commits before opening the
   note.

On Windows, `scripts/sync_obsidian_vault.ps1` performs a safe fast-forward-only
pull. The local setup creates a scheduled task that runs this script hourly;
it will never merge over local vault edits.

The workflow itself needs no API key or stored personal access token. It uses
the built-in `GITHUB_TOKEN` and the `copilot-requests: write` permission.

## Content and source policy

- The configured inputs are daily cyber-news RSS feeds: The Record,
  BleepingComputer, and The Hacker News. The default never scrapes individual
  article pages; it uses the RSS title and summary only. This keeps load low and
  avoids treating an RSS feed as a licence to crawl or republish source text.
- Add or remove sources only in `config/sources.yaml`; keep RSS/API endpoints
  rather than letting the AI discover arbitrary sites.
- The vault publishes an original short Japanese summary, source URL, evidence
  type, and confidence. It does not reproduce article text or translations.
- `state/brief_state.json` is committed after a successful render, preventing
  duplicate articles from appearing again. Failed model runs leave the state
  untouched for a safe retry.

## Obsidian and self-hosting

Obsidian is a local Markdown vault, not a receiving API. Make the clone of this
repository the vault itself, or clone it under an existing vault. A self-hosted
site can deploy from the same private repository by pulling it and rebuilding a
static site after each commit. Deployment credentials are intentionally not
included here because the server and deployment method have not been specified.

## Local checks

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/daily_brief.py collect --config config/sources.yaml --state state/brief_state.json --output .runtime/candidates.json
```

The last command only collects candidates. The Copilot command is run by
GitHub Actions, where the repository `GITHUB_TOKEN` has the correct entitlement
and permissions.
