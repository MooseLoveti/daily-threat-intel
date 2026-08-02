# Daily Intelligence Vault

This private repository generates two Obsidian-compatible Japanese daily reports
at 06:00 JST with GitHub Actions and GitHub Copilot CLI.

| Report | Inputs and purpose | Markdown output |
| --- | --- | --- |
| Threat intelligence | The Record, BleepingComputer, and The Hacker News; incidents, actors, campaigns, and vulnerabilities | `content/daily/YYYY-MM-DD.md` |
| AI news | Separate AI-security, AI-lab, and research RSS inputs; AI security, announcements/benchmarks, and research | `content/ai-daily/YYYY-MM-DD.md` |

The two reports have separate source configurations, deduplication state files,
and Copilot prompts. They are committed together only after both are rendered.

## How it works

1. GitHub Actions reads configured RSS feeds into bounded candidate lists.
2. Copilot CLI categorizes and writes concise Japanese summaries from those
   candidates only. It receives no shell, browser, network, SSH, or repository
   writing tools.
3. Python validates the returned JSON and produces Markdown from a fixed
   template. Only source URLs collected from RSS can appear in the report.
4. Actions commits the Markdown and state files to this private repository.
5. Obsidian on the phone pulls the desired report folders with Easy Git.

Each report considers at most 24 candidates per run. The default uses RSS titles
and summaries only; it does not crawl source article pages.

## Configuration

- `config/sources.yaml`: threat-intelligence sources, categories, and limits.
- `config/ai_sources.yaml`: independent AI-news sources, categories, and limits.
- `state/brief_state.json`: threat-report last successful run and 90-day
  duplicate history.
- `state/ai_brief_state.json`: independent AI-news duplicate history.

The AI-news configuration uses AI-specific feeds from OpenAI, Google DeepMind,
and arXiv cs.AI. General cyber-news sources are filtered to AI-related terms.
Add or remove RSS feeds in the matching YAML configuration; do not let the AI
choose arbitrary sites.

## Report format

The Markdown shows only categories that contain news. It omits retrieval source
and period banners, empty-category messages, confidence, evidence type, and
machine classification labels. Source links remain with each item.

## Phone-only Obsidian setup

No PC, Windows task, or Obsidian Sync subscription is needed. The phone pulls
the completed Markdown from GitHub when Obsidian opens.

Use Easy Git and create these two **pull-only** mappings in the same iCloud
vault. The existing PAT for `MooseLoveti/daily-threat-intel` can be reused; no
new token is needed.

| Local Obsidian folder | Repository path | Direction | Auto mode |
| --- | --- | --- | --- |
| `脅威インテリジェンス` | `content/daily` | Pull only | On startup |
| `AIニュース` | `content/ai-daily` | Pull only | On startup |

For each mapping, select repository `MooseLoveti/daily-threat-intel` and branch
`main`. Run `Sync mapping` once after creating a mapping, then opening Obsidian
will pull later updates automatically.

## Local checks

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/daily_brief.py collect --config config/sources.yaml --state state/brief_state.json --output .runtime/threat-candidates.json
python scripts/daily_brief.py collect --config config/ai_sources.yaml --state state/ai_brief_state.json --output .runtime/ai-candidates.json
```

The Copilot calls run only in GitHub Actions, using the repository `GITHUB_TOKEN`
and the repository owner's active Copilot entitlement.
