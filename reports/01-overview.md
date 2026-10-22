# The open PR queue on `oven-sh/bun` — what 5,653 PRs are actually about

**Snapshot:** 2026-10-22, ~09:30 UTC
**Latest Bun release at snapshot:** 1.4.3 (2026-10-10)
**Source:** GitHub REST API, every open PR, all 57 pages, deduplicated (5,653 unique, zero
pagination drift)

---

## 1. The headline: this is one agent's work queue

| | PRs | Share |
|---|---:|---:|
| `robobun` — the automated agent | **4,534** | **80.2%** |
| Everyone else (maintainers + community) | 1,119 | 19.8% |

4,485 PRs carry the `claude` label. The three biggest human contributors are
`Jarred-Sumner` (198), `dylan-conway` (119) and `steipete` (83) — together, 7% of the
queue.

This changes how the rest of this report should be read. A normal open-source PR queue is
a backlog of *human intent*; you can estimate "what does this project want" from it. This
is not that. It is a stream of small, individually-reviewed-by-nobody fixes produced by an
agent, at a sustained rate:

| Week (relative) | PRs opened |
|---|---:|
| this week (partial) | 810 |
| 1 week ago | 257 |
| 2 weeks ago | 163 |
| 3 weeks ago | 183 |
| 4 weeks ago | 365 |
| 5 weeks ago | 359 |
| 6 weeks ago | 487 |
| 7 weeks ago | 233 |

Roughly 160–490 per week over the recent full weeks. At that rate the queue cannot be
drained by review alone, and indeed it is not being drained: the **median open PR is 54
days old**, and 108 are more than a year old.

## 2. What the work is

| Category | PRs | Share | What it means |
|---|---:|---:|---|
| **Fix** | 4,385 | 77.6% | Corrects behaviour: a crash, a wrong result, a Node-parity gap, a hang, a hardening change |
| **Test** | 432 | 7.6% | Test-only: new coverage, de-flaking, faster suites |
| **Feature** | 380 | 6.7% | New API, new flag, new platform, behaviour that did not exist |
| **Docs** | 184 | 3.3% | Docs, guides, types prose |
| **Chore / CI / deps** | 133 | 2.4% | WebKit bumps, dependency pins, build tooling |
| **Performance** | 53 | 0.9% | Speed/memory where the point is the cost |
| **Security** | 38 | 0.7% | Title names a vuln class, CVE/GHSA or advisory |
| **Refactor** | 7 | 0.1% | Internal restructuring |
| **Unclassified** | 41 | 0.7% | Residue |

Two things to note about these numbers.

**The taxonomy is heuristic.** It is built from each PR's own `What`/`Problem` section
plus its title, with a title-weighted vocabulary. Spot-checking 30 random rows per
category, I would put agreement at roughly 80–85%: the errors are mostly features
described as behaviour changes ("bun:sqlite: reset an EXPLAIN statement…") and fixes that
read like features. The **one-line gist in the inventory is the author's own text**, so
where the label is wrong the description next to it is still right. Treat the category as
a filter, not a fact.

**Fixes dominate because the base rate dominates.** The agent's output is overwhelmingly
small parity fixes against Node — 794 PRs mention `node:` in the title. That is genuinely
useful work; it is also why the queue grows faster than it can be reviewed.

> On the two security numbers: the table's **38** counts PRs whose *title* names a vuln
> class, a CVE/GHSA or an advisory. Widening the net to any PR that hardens an
> untrusted-input path — bounds checks, malformed-request rejection, escaping, sandboxing —
> gives **202**. The 38 are the ones a maintainer would triage first; the 202 are the ones
> that matter if you are looking for the fix you missed. Both are enumerated in
> [`03-security-triage.md`](03-security-triage.md).

## 3. Which subsystems

Top areas by title prefix (1544 PRs have no `area:` prefix at all):

| Area | PRs |
|---|---:|
| `bundler` | 216 |
| `test` | 181 |
| `docs` | 147 |
| `css` | 138 |
| `js_parser` | 108 |
| `Bun.serve` | 98 |
| `shell` | 89 |
| `install` | 83 |
| `bun test` | 79 |
| `resolver` | 51 |
| `fetch` | 48 |
| `ci` | 44 |
| `build` | 42 |
| `node` | 38 |
| `Bun.Image` | 38 |
| `cli` | 38 |
| `bun-types` | 35 |
| `react-compiler` | 32 |
| `spawn` | 31 |

Theme clusters worth knowing about, because they tell you where the project is heading:

* **`node:` parity is the single biggest thread** — 795 PRs. `node:quic` alone has 40,
  `node:http`/`http2` around 60, `node:fs`, `node:vm`, `node:wasi`, `node:worker_threads`
  all well represented. The project is chasing Node compatibility module by module, one
  behaviour at a time.
* **A new toolchain is being built in public**: `bun check` (19 PRs), `bun lint` (7),
  `bun fmt` (4), `bun bake` (3). These are young enough that the PRs read like bug reports
  against a prototype.
* **`Bun.Image` (38)** is growing a real codec stack — JPEG XL decode/encode, WebP, ICC
  profiles. Binary parsers, which is where the memory-safety work is (see the security
  report).
* **WebKit bumps** are a recurring chore (one every few days at peak); they carry JS-engine
  memory-safety fixes and are the main channel by which JSC bugs reach Bun.
* **`webview` (35)** and **`s3` (63)** are lower-traffic but security-adjacent surfaces.

## 4. How old, and how big

| Age of PR | PRs |
|---|---:|
| ≤ 7 days | 856 |
| 8–30 days | 642 |
| 31–90 days | 3,308 |
| 91–180 days | 594 |
| 181–365 days | 145 |
| > 1 year | 108 |

Median: **55 days**. The 31–90 day band is a cliff — that is where PRs go to wait, and it
is where the security fixes in the companion report are sitting.

**A caveat on size data:** the REST *list* endpoint omits `additions`, `deletions` and
`changed_files`, and the snapshot did not fetch per-PR details for all 5,653. Sizes quoted
in this report come from per-PR calls made for the 202 security-relevant PRs and for
individually discussed PRs. I have not estimated sizes for the rest.

## 5. PRs worth reading on their own merits

Not security, just the interesting ones. These show the range of what is in the queue:

* **#45631** — `bun build --compile --aot`: compile TypeScript to machine code ahead of
  time. The most ambitious PR in the queue.
* **#46383** — `bun check`: TypeScript 7.1 support.
* **#45973** — stop storing the runtime's `.bss` in Linux executables (~1.8 MB saved).
* **#46329** — bindgen: move the remaining 61 classes to schemas and delete
  `generate-classes.ts`. Large internal restructuring.
* **#46023** — `Bun.Image`: decode and encode JPEG XL.
* **#35403** — `--permission`: a full permission model (`process.permission`, `node:fs` and
  `node:net` enforcement, 10 upstream tests). Security-relevant as a *feature*.
* **#46351** — the brotli CVE fix (see the security report).
* **#42086** — "constant-time" in the title refers to runtime, not cryptography: a
  calendar operation that took 23 s now does not.

## 6. The process finding

The queue is not short of good work. It is short of review throughput, and the review that
does happen is not triaged by risk.

* **One label exists** (`claude`, on 4,484 PRs). There is no `security` label, no
  `needs-review`, no priority axis. Nothing in the API tells a maintainer which of 5,653
  PRs would break a user's week.
* **Drafts: 367** (226 from the agent). Some are genuinely WIP; others appear to be
  finished work parked as draft.
* **The labels are near-useless for filtering.** `claude` is on 4,485 PRs (79%); the next
  most common label — `breaking` — is on 4, and everything else (`bundler`,
  `dependencies`, `docs`, `node:crypto`, `types`, `github_actions`, `codex`) is on one PR.

The practical consequence, developed in
[`02-security-severity.md`](02-security-severity.md): **42% of the security-relevant PRs no
longer apply to `main`**, and the one remote memory-corruption bug in the queue was fixed
on `main` by a dependency bump while the PR that documents it sat blocked on CI.

---

*Companions: [`02-security-severity.md`](02-security-severity.md) ·
[`03-security-triage.md`](03-security-triage.md) · [`inventory/`](inventory/) ·
[`prs.csv`](prs.csv)*
