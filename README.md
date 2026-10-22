# bun-scan

An evaluation of **every open pull request on [`oven-sh/bun`](https://github.com/oven-sh/bun/pulls)** —
what each one is for, and how bad the security ones are.

**Queue snapshot:** 2026-10-22 · **5,653 open PRs**
**Release analysed:** Bun **1.4.3** · **Latest release: 1.4.4** (2026-10-22)

---

## Status right now

**1.4.4 is out, and it fixes 27 security issues — including all three published advisories
that named Bun as unpatched.** Nine findings from this evaluation survive the upgrade.

| | 1.4.3 | **1.4.4** |
|---|---|---|
| Published advisories open | 3 | **0** |
| Certificate-validation bypasses | 9 | **0** |
| Findings from this report fixed | — | **6 of 15** |
| Findings outstanding | 15 | **9** |

`main` is currently identical to the `bun-v1.4.4` tag, so none of the outstanding nine is
"fixed but unreleased" — they are open, full stop, each with the PR that would close it.

### The one to care about if you upgrade for nothing else

**F2 — `HTMLRewriter`'s comment setter is an HTML-injection bypass.** `-->` is rejected but
`--!>`, `>`, `->` are not, so anything after them becomes live markup. I reproduced the XSS
on a real Bun in three lines. The fix needs the lol-html pin to move; it has not, and the
upgrading PR (#43266) is still open. **1.4.4 does not fix this.**

The other eight outstanding: URLPattern and HTTP/2 DoS (F4, F5), the `bun add`
supply-chain gap (F3), HTTP/2 `originSet` (F10), the `mkdir` symlink escape (F6), WASI
pointer bounds (F7), the cron `/tmp` path (F8), and `bun audit` failing open (F9). Full
status: [reports/06-release-gap.md](reports/06-release-gap.md) Part B.

### What 1.4.4 actually fixed

Reconstructed from the 171 merged PRs, because the release page carries no changelog —
[reports/07-1.4.4-changelog.md](reports/07-1.4.4-changelog.md):

- **brotli CVE-2026-111497** — remote OOB write via `fetch()` on `Content-Encoding: br`.
  Every release up to 1.4.3 was affected.
- **QPACK amplification** — one connection could OOM an HTTP/3 server at ~4000×.
- **eMudhra CA compromise** — the 8 compromised intermediates are now blocked.
- **Nine TLS certificate-validation bypasses**, never filed as advisories: WebSocket never
  checked the hostname, `NODE_TLS_REJECT_UNAUTHORIZED=0` disabled a *server's* client-cert
  enforcement, `tls: []` to `Bun.listen` was plaintext, `PGSSLMODE=verify-*` was dropped.
- **Postgres never verified the certificate hostname.**
- **A WebSocket parser desync** and an unbounded ping queue.
- **~300 crash paths** hardened via two consolidation PRs.

The release is more security-dense than its changelog suggests: if the TLS and SQL items
had been filed as CVEs, 1.4.4 would be a security release by any definition.

There is one regression: `emSign Root CA - G1` was restored by a later PR that undid an
earlier root removal. Not exploitable — the compromised chain roots to a different CA that
Bun does not trust at all — but a deliberate removal was undone, and the test that
documented it went with it.

---

## The study

| | |
|---|---|
| Open PRs evaluated | **5,653** |
| Authored by `robobun` (an automated agent) | **4,534 (80%)** |
| Fixes / features / tests / docs / perf | 77.6% / 6.7% / 7.6% / 3.3% / 0.9% |
| Median PR age | **55 days** |
| Security-relevant PRs | **202** |
| Security PRs that no longer apply to `main` | **84 (42%)** |
| Security PRs mergeable and clean | **4** |

**Fifteen findings.** Six are fixed in 1.4.4; nine are outstanding.

Detection and patching work; **shipping lagged**. Three high-profile issues in three days —
brotli, the [FoxIO QPACK amplification attack](https://foxio.io/blog/header-accordions-qpack-amplification-attacks-against-http-3-servers)
(F11), and the [eMudhra CA compromise](https://emudhra.we-have-a-problem.com/) (F12) — were
patched on `main` within a day and sat unreleased for up to twelve days.

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
| [reports/07-1.4.4-changelog.md](reports/07-1.4.4-changelog.md) | Security changelog for 1.4.4 |
| [reports/inventory/](reports/inventory/) | All 5,653 PRs, one row each, grouped by purpose |
| [reports/prs.csv](reports/prs.csv) | The same classification, machine-readable |

## Method

1. **Collect** every open PR via the GitHub REST API (57 pages, deduplicated).
2. **Classify** by purpose from title + the PR's own `What`/`Problem` section, plus a
   taxonomy of vulnerability classes and hardening signals → 202 security candidates.
3. **Read** every security candidate in full; read the diff where it decided a rating.
4. **Verify** each finding against `main` and the released tag — is the dependency pin
   still vulnerable, does the code still have the bug, is the CVE real and fixed
   elsewhere? For 1.4.4 every claim was re-checked in the files at `bun-v1.4.4`.
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

`data/` (raw API responses, ~250 MB with the previous snapshot kept for diffing) is
gitignored. Nothing else is.

## On the reproductions

Six findings were confirmed by running a reproduction against Bun 1.4.0. The observed
output is quoted inline in the reports. The scripts themselves are **not published here** —
each reproduction also appears in the public pull request that reports the bug, and those
are linked from every finding.
