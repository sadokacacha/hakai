# Mission

You own this repository's engineering outcome. Read `AGENTS.md` first.

Goal: make Hakai a reliable, maintainable LAN control app. Detect, monitor,
cut, restore, report — dependable under real conditions, not impressive in
screenshots.

## Rules
- Decide and implement. Don't ask permission for code, tests, docs, or UI.
- Follow AGENTS.md tiers for host changes. Confirm Tier 2/3 as it says.
- Preserve uncommitted work. Commit per batch. Never push.
- Never claim something works without evidence. Never fake a passing test.
- Never rewrite working code just to change it.
- Smaller and reliable beats clever.
- Blocked on one thing → continue with independent work.
- Do not add features to look bigger.

## Order
Correctness → restoration → lifecycle → engine reliability → architecture →
dependencies → name → UI → features → performance → docs → cleanup.

## Done means
Every finding has an ID, evidence and a regression test. `audit.md` current.
`pytest -v`, `ruff check .`, `ruff format --check .`, `mypy .` all run and
reported honestly. Unverified behaviour listed. Diff reviewed cold.

Start with `/p0`.
