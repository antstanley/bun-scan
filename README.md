# bun-scan

An evaluation of **every open pull request on [`oven-sh/bun`](https://github.com/oven-sh/bun/pulls)** —
what each one is for, and how bad the security ones are.

**Snapshot:** 2026-10-22, ~09:30 UTC · **5,653 open PRs** · Bun latest release **1.4.3**

---

## The short version

| | |
|---|---|
| Open PRs evaluated | **5,653** |
| Authored by `robobun` (an automated agent) | **4,534 (80%)** |
| Fixes / features / tests / docs / perf | 77.6% / 6.7% / 7.6% / 3.3% / 0.9% |
| Median PR age | **54 days** |
| Security-relevant PRs | **202** |
| Security PRs that no longer apply to `main` | **84 (42%)** |
| Security PRs mergeable and clean | **4** |

**Fifteen findings.** Two matter more than the rest:

1. **brotli decoder OOB write, CVE-2026-111497** — remote, unauthenticated, reachable
   through `fetch()` on any `Content-Encoding: br` response. Every released Bun is
   affected. `main` is already fixed; **1.4.3 is not**.
2. **`HTMLRewriter` comment setter is an HTML-injection bypass** — `-->` is rejected but
   `--!>`, `>`, `->` are not, so injected markup goes live. Reproduced XSS. **Not fixed
   anywhere.**

Plus a structural result: detection and patching work; **shipping lagged**. Three
high-profile issues in three days — brotli, the [FoxIO QPACK amplification
attack](https://foxio.io/blog/header-accordions-qpack-amplification-attacks-against-http-3-servers)
(F11), and the [eMudhra CA compromise](https://emudhra.we-have-a-problem.com/) (F12) — were
patched on `main` within a day and sat unreleased for up to twelve days. **1.4.4 shipped on
2026-10-22 and contains all three**, plus 24 further issues that were never filed as
advisories.

## Read

| File | What it is |
|---|---|
| **[reports/README.md](reports/README.md)** | The index and the full summary |
| [reports/01-overview.md](reports/01-overview.md) | The shape of the queue: who writes it, what it is, how old |
| [reports/02-security-severity.md](reports/02-security-severity.md) | **The deep dive** — 15 findings, CVSS 3.1, 6 verified with proofs of concept |
| [reports/03-security-triage.md](reports/03-security-triage.md) | All 202 security-relevant PRs, rated, including the non-findings |
| [reports/04-advisory-check.md](reports/04-advisory-check.md) | Two public advisories checked against Bun |
| [reports/05-next-release.md](reports/05-next-release.md) | What shipped in 1.4.4 — verified against the tag |
| [reports/06-release-gap.md](reports/06-release-gap.md) | **What 1.4.3 was exposed to, what 1.4.4 fixed, and what remains** |
| [reports/inventory/](reports/inventory/) | All 5,653 PRs, one row each, grouped by purpose |
| [reports/prs.csv](reports/prs.csv) | The same classification, machine-readable |

## Method

1. **Collect** every open PR via the GitHub REST API (57 pages, deduplicated).
2. **Classify** by purpose from title + the PR's own `What`/`Problem` section, plus a
   taxonomy of vulnerability classes and hardening signals → 202 security candidates.
3. **Read** every security candidate in full; read the diff where it decided a rating.
4. **Verify** each finding against `main` and the released tag — is the dependency pin
   still vulnerable, does the code still have the bug, is the CVE real and fixed
   elsewhere?
5. **Reproduce** six of them against a local Bun 1.4.0.

Known limits, stated in the reports and worth repeating: the purpose taxonomy is
heuristic (~80–85% on spot checks, so every row carries the author's own description
alongside the label); CVSS scores are mine and argued in place; and the snapshot moves.

## Reproducing

```sh
./scripts/fetch_pulls.sh          # all open PRs -> data/pages/
python3 scripts/classify.py       # taxonomy + security tiers
python3 scripts/build_reports.py  # prs.csv + inventory/
python3 scripts/build_triage.py   # 03-security-triage.md
```

`data/` (the raw API responses, ~147 MB) is gitignored. Nothing else is.

## On the reproductions

Six findings were confirmed by running a reproduction against Bun 1.4.0. The observed
output is quoted inline in the reports. The scripts themselves are **not published here** —
each reproduction also appears in the public pull request that reports the bug, and those
are linked from every finding.
