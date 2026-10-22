# Evaluation of every open pull request on `oven-sh/bun`

**Snapshot taken:** 2026-10-22, ~09:30 UTC
**Scope:** all **5,652** open PRs at that moment
**Question asked:** what is each PR for, and how bad are the security ones?

---

## Read in this order

| File | What it is |
|---|---|
| **[01-overview.md](01-overview.md)** | The shape of the queue: who writes it, what kind of work it is, how old it is. Start here. |
| **[02-security-severity.md](02-security-severity.md)** | **The deep dive.** Twelve findings rated with CVSS 3.1 — reach, attacker model, impact, and for six of them a proof of concept I ran against Bun 1.4.0 — plus a hardening bundle that does not fit the shape. |
| **[03-security-triage.md](03-security-triage.md)** | All 202 security-relevant PRs in one table, each with a rating and a one-line verdict. Includes the ones I decided are *not* vulnerabilities. |
| **[04-advisory-check.md](04-advisory-check.md)** | The detailed appendix for F11 and F12 — the FoxIO QPACK amplification attack and the eMudhra intermediate CA compromise — with the reproduction commands. Both are fixed on `main` and in **no release**. |
| **[inventory/](inventory/)** | All 5,652 PRs, one row each, grouped by what the PR is for. Every row carries the author's own description of the change. |
| **[prs.csv](prs.csv)** | The same classification, machine-readable. |

## The answer in one screen

**Composition.** 80% of the queue (4,533 PRs) is authored by `robobun`, an automated
agent. 77.6% of all open PRs are fixes, 6.7% features, 3.3% docs, 0.9% performance, 0.7%
security. Median PR age: 54 days.

**Security.** 202 PRs touch a security-relevant surface. Thirteen findings are worth acting on:

| | PR | What | Severity |
|---|---|---|---|
| 1 | [#46351](https://github.com/oven-sh/bun/pull/46351) | brotli decoder OOB write, **CVE-2026-111497** — remote, via `fetch()` on `Content-Encoding: br` | **8.1 High** |
| 2 | [#42646](https://github.com/oven-sh/bun/pull/42646) | `HTMLRewriter` comment setter is an HTML-injection bypass → XSS | **6.1 Med** (8.0 privileged) |
| 3 | [#45204](https://github.com/oven-sh/bun/pull/45204) | `bun add <url>` inherits `trustedDependencies` trust → lifecycle RCE | **7.1 High** |
| 4 | [#42535](https://github.com/oven-sh/bun/pull/42535) | `URLPattern` polynomial backtracking → DoS | **7.5 High** |
| 5 | [#36410](https://github.com/oven-sh/bun/pull/36410) | HTTP/2 CONTINUATION flood (CVE-2024-28182) → DoS | **7.5 High** |
| 6 | [#38298](https://github.com/oven-sh/bun/pull/38298) | recursive `mkdir` follows a dangling symlink → write outside the directory | **5.9 Med** |
| 7 | [#34468](https://github.com/oven-sh/bun/pull/34468) | `node:wasi` never bounds-checks guest pointers | **5.5 Med** |
| 8 | [#29144](https://github.com/oven-sh/bun/pull/29144) | `Bun.cron()` predictable `/tmp` log path → local symlink attack | **5.0 Med** |
| 9 | [#45668](https://github.com/oven-sh/bun/pull/45668) + [#46143](https://github.com/oven-sh/bun/pull/46143) | `bun audit` reports "clean" when it is not | control bypass |
| 10 | [#42411](https://github.com/oven-sh/bun/pull/42411) | HTTP/2 client `originSet` grows unbounded | **6.5 Med** |
| 11 | [#33191](https://github.com/oven-sh/bun/pull/33191) | node:http/http2 hardening bundle (unvalidated h2 pseudo-headers, failures reported as `200`) | varies |
| 12 | [#46392](https://github.com/oven-sh/bun/pull/46392) | QPACK header amplification, HTTP/3 — one connection OOMs the server (**merged, unreleased**) | **7.5 High** |
| 13 | [#46300](https://github.com/oven-sh/bun/pull/46300) | eMudhra intermediate CA compromise — Bun distrusts none of the 8 (**merged, unreleased**) | **8.7 High** |

Severity here is the CVSS score. The triage file uses an **action** rating, which is
harsher at the top: #46351 is "Critical" there — remote, unauthenticated memory corruption,
shipped to every user — despite scoring 8.1, because exploitation needs heap grooming.
That is the only place the two scales disagree, and the reasoning is in
[02 §F1](02-security-severity.md#f1--brotli-decoder-oob-write--cve-2026-111497).

**The two that matter most.**

`#46351` is a remote heap out-of-bounds write in the brotli decoder, reachable by default
from `fetch()`. Every released Bun is affected. **`main` is already fixed** — it moved to
brotli v1.2.1 on 2026-10-21, the same day Node shipped its fix — but **1.4.3 still pins
v1.2.0**. The exposure is a missing release, not a missing patch.

`#42646` is a sanitizer bypass that is **still unfixed on `main`**. The comment setter
rejects `-->` but not `--!>`, `>` or `->`, so text after those sequences becomes live
markup. I reproduced the XSS on 1.4.0 in one line.

**The structural finding.** 84 of the 202 security PRs (42%) no longer apply to `main`;
only 4 are mergeable and clean; the median security PR has waited 68 days. Detection is
working — several findings say *"an audit found this, no user reported it"*. Delivery is
not.

**Three fixes on `main`, zero released.** F1 (brotli, CVE-2026-111497), F11 (QPACK
amplification) and F12 (eMudhra CA) are all fixed on `main` and all absent from 1.4.3 —
in F11 and F12's case because each advisory, published 2026-10-20, was patched within a
day and no release has followed. The release channel, not the review queue, is now the
binding constraint. See [04-advisory-check.md](04-advisory-check.md).

## Method, and its limits

1. **Collect.** All open PRs via the GitHub REST API, 57 pages, deduplicated against
   pagination drift (5,652 unique).
2. **Classify.** A title-weighted vocabulary over each PR's title and its own
   `What`/`Problem` section, plus an explicit taxonomy of vulnerability classes, CVE/GHSA
   identifiers, and hardening signals. 202 security candidates in four tiers.
3. **Read.** Every `explicit` and `vuln-class` PR read in full; the diff read where it
   mattered.
4. **Verify.** Each finding checked against `main` and against the released tag — does the
   dependency pin still contain the bug? does the code still have it? Is the CVE real and
   fixed elsewhere? Table of checks in
   [02-security-severity.md §2](02-security-severity.md#2-how-i-worked-and-how-much-to-trust-each-claim).
5. **Reproduce.** Six PoCs executed against a local Bun 1.4.0 — HTML injection, the symlink
   escape, WASI pointer handling, `URLPattern` timing, duplicate `Host`, and the
   deep-nesting SIGSEGV. Scripts in [`../poc/`](../poc/).

**Limits you should hold me to:**

* The purpose classification is heuristic, ~80–85% on a spot check. The gist next to each
  label is the author's own text, so a wrong label still sits beside a right description.
* I did not audit Bun for memory safety. I evaluated what the open PRs *claim*, and
  checked the claims that decided a rating.
* CVSS scores are mine, argued in place. They are for the realistic path, not the worst
  case, and I say where I think the number overstates the practical risk.
* The snapshot moves. PRs were being opened while I worked (the newest was #46477 at
  collection time). Numbers are point-in-time.
* The list endpoint omits `additions`/`deletions`/`changed_files`, so sizes appear only for
  PRs I fetched individually.

## Reproducing this

```sh
./scripts/fetch_pulls.sh      # all open PRs -> data/pages/
python3 scripts/classify.py   # taxonomy + security tiers -> data/prs_classified.json
python3 scripts/build_reports.py   # reports/prs.csv + reports/inventory/
python3 scripts/build_triage.py    # reports/03-security-triage.md
```

Raw data is kept in `data/` (uncommitted, ~180 MB with per-PR details).
