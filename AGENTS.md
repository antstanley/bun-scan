# AGENTS.md

Instructions for an agent asked to **redo or refresh these scans**.

This repository holds an evaluation of the open pull requests on
[`oven-sh/bun`](https://github.com/oven-sh/bun) plus a release-gap analysis. Everything in
`reports/` is generated from data under `data/` (gitignored) or written by hand from it.

---

## 1. What the deliverables are

| Path | Generated or hand-written |
|---|---|
| `reports/inventory/*.md` | **generated** by `scripts/build_reports.py` |
| `reports/prs.csv` | **generated** by `scripts/build_reports.py` |
| `reports/03-security-triage.md` | **generated** by `scripts/build_triage.py` |
| `reports/01-overview.md` | hand-written; **numbers must be refreshed by hand** |
| `reports/02-security-severity.md` | hand-written (findings F1–F15) |
| `reports/04-advisory-check.md` | hand-written appendix for F11/F12 |
| `reports/05-next-release.md` | hand-written; what shipped in 1.4.4, verified at the tag |
| `reports/06-release-gap.md` | hand-written; **the bottom line** — what 1.4.3 was exposed to and what remains |
| `README.md`, `reports/README.md` | hand-written indexes with headline numbers |
| `reports/07-1.4.4-changelog.md` | hand-written security changelog, one per release |
| `reports/08-tls-disclosure.md` | hand-written; disclosure analysis for the 1.4.4 TLS fixes |

There are two independent scans. Run whichever the task needs; the release-gap one is the
one that answers "is the current release vulnerable".

---

## 2. Prerequisites

```sh
gh auth status          # needs 'repo'; all calls below are authenticated
jq --version            # used by the shell scripts
python3 --version       # 3.10+
```

Authenticated rate limit is 5,000 requests/hour. A full refresh of the open-PR scan is
**57 requests**; the release scan is ~172.

`bun` is only needed if you want to reproduce findings locally (see §7).

---

## 3. Scan A — every open PR (the inventory)

```sh
./scripts/fetch_pulls.sh          # -> data/pages/page_*.json  (57 pages, ~3 min)
python3 scripts/classify.py       # -> data/prs_classified.json
./scripts/fetch_sec_details.sh    # -> data/sec/*.json for the 202 security-tier PRs
python3 scripts/build_reports.py  # -> reports/prs.csv + reports/inventory/
python3 scripts/build_triage.py   # -> reports/03-security-triage.md
```

`fetch_pulls.sh` **skips pages that already exist**. To take a fresh snapshot, move the old
one aside first — and keep it, because the diff is useful:

```sh
mv data/pages data/pages.prev
./scripts/fetch_pulls.sh
```

Then compare snapshots to report the delta:

```python
new = {p["number"] for p in json.load(open("data/all_prs_raw.json"))}
old = {p["number"] for p in json.load(open("data/all_prs_prev.json"))}
```

`build_triage.py` needs `data/sec_details.json`, which is built from `data/sec/*.json`
after `fetch_sec_details.sh` — see the snippet in §6 if you need to rebuild it.

---

## 4. Scan B — what merged since the last release (the release gap)

This is the scan that answers "what is the current release vulnerable to that will be
patched".

```sh
# 1. what is the latest release?
gh api repos/oven-sh/bun/releases/latest -q '.tag_name + "  " + .published_at'

# 2. what is on main that is not in it?
gh api "repos/oven-sh/bun/compare/bun-v1.4.4...main" > data/next/compare.json

# 3. extract PR numbers from commit subjects, then fetch each PR
./scripts/fetch_next_release.sh

# 4. classify them
python3 -c "
import json,glob,sys; sys.path.insert(0,'scripts'); import classify
prs=[]
for f in glob.glob('data/next/pr/*.json'):
    d=json.load(open(f))
    prs.append({'number':d['number'],'title':d['title'],'user':d['user']['login'],
                'body':d.get('body') or '','merged_at':d.get('merged_at'),'url':d['html_url'],
                'draft':d.get('draft'),'changed_files':d.get('changed_files'),
                'additions':d.get('additions'),'deletions':d.get('deletions')})
for p in prs: p.update(classify.classify(p))
json.dump(prs, open('data/next/classified.json','w'), indent=1)
"
```

When a new release ships, update the tag in every place the reports mention it — the
`bun-vX.Y.Z` in the commands above, and the "Previous / Current release" lines in
`reports/05-next-release.md` and `reports/06-release-gap.md`.

**Check the cut point first.** `compare/bun-vTAG...main` with `ahead=0, behind=0` means the
tag *is* `main`'s head, so nothing you scrolled through was left out. If it is not, some of
what you listed never shipped — diff it before claiming anything is in the release.

**Verify at the tag, not on `main`.** `main` moves; the tag does not. Every headline claim
in `reports/05-next-release.md` §8 is a `gh api ...?ref=bun-vX.Y.Z` check for this reason.

---

## 5. What to refresh in the hand-written prose

Generated files take care of themselves. These numbers do not, and will silently go stale:

| Figure | Appears in |
|---|---|
| total open PRs, `robobun` count, `claude` label count | `README.md`, `reports/README.md`, `reports/01-overview.md`, `reports/02` (§22) |
| category counts (fix / feature / test / …) | `reports/01-overview.md` |
| age buckets and median age | `reports/01-overview.md`, `reports/02` (§22) |
| per-week opening rate | `reports/01-overview.md` |
| top areas table | `reports/01-overview.md` |
| merge-state counts (dirty / blocked / clean) | `reports/02` (§22), `reports/README.md` |
| commits and PRs merged since the tag | `reports/05`, `reports/06` |

Compute them, don't retype from memory:

```python
import json, datetime, statistics
from collections import Counter
p = json.load(open("data/prs_classified.json"))
now = datetime.datetime.now(datetime.timezone.utc)
age = lambda s: (now - datetime.datetime.fromisoformat(s.replace("Z","+00:00"))).days
ages = [age(x["created_at"]) for x in p]
print(len(p), sum(1 for x in p if x["user"]=="robobun"), statistics.median(ages))
print(Counter(x["category"] for x in p).most_common())
```

Then grep for leftovers: `grep -rn "5,652" README.md reports/*.md` — a missed number is
the most common defect in a refresh.

---

## 6. Gotchas that cost real time

**The REST list endpoint omits fields.** `GET /repos/{o}/{r}/pulls` does **not** return
`changed_files`, `additions`, `deletions`, `comments` or `commits` — they come back `null`.
Fetch the individual PR if you need them. Do not report size or engagement from the list.

**`jq` treats `""` as truthy.** `select(.security_tier)` matches every row, because only
`false` and `null` are falsy. Use `select(.security_tier != "")`.

**Titles are a terrible index of security content.** On this repo the most important
security PRs had innocuous titles: *"tls: reject chains containing blocked public keys"*,
*"Fix regressions since 1.4.3 … and update brotli"*, *"http3: lift lsquic's limits"*. The
classifier missed all three. **Always cross-check the classification against the actual
tag→main diff and read the consolidation PRs by hand.**

**Consolidation PRs absorb open PRs.** An open PR number does **not** mean the bug is
unfixed. `#46021` folds in 306 PRs (227 whole), `#46270` more. Parse the `#\d+` references
inside those bodies to see whether an open PR's content already shipped.

**Distinguish a 1.4.3 vulnerability from a post-release regression.** Several fixes in the
1.4.4 diff repair damage introduced by consolidation PRs that never shipped (`#45124`,
`#45139`, `#45477`, `#46480`, and the regression list in `#46270`). Counting them inflates
the exposure figure. Read the body for phrases like *"Regressions from #44618, not in a
release"*.

**Verify claims against the tree, not the PR text.** PR descriptions are written by the
same agents that write the code and go stale fast. Pin the check to a ref:

```sh
gh api "repos/oven-sh/bun/contents/path/to/file?ref=bun-v1.4.3" -q .content | base64 -d
gh api "repos/oven-sh/bun/contents/path/to/file" -q .content | base64 -d          # main
```

**Pagination drifts.** New PRs arrive while you page. Always dedupe by `number` and assert
`unique == length` before analysing.

**`mergeable_state` is lazy.** `unknown` means GitHub has not computed it yet; re-request
the PR. `dirty` means it conflicts with `main`.

**The classifier is heuristic** — roughly 80–85% agreement on a spot check. Say so when you
present its output, and always show the author's own summary next to the label.

---

## 7. Reproducing findings

Local reproduction was done against a Bun the machine already had. If you reproduce
anything:

* Record the exact `bun --version`. Findings are version-specific.
* Check whether the bug is still live before claiming it: the HTMLRewriter one needs
  `scripts/build/deps/lolhtml.ts` to still pin the pre-fix commit.
* **Do not commit proof-of-concept scripts.** This repository had them removed from the
  tree *and* from history on request. The rule now is: quote the observed output inline in
  the relevant finding, and link the public PR that reports the bug. Each PoC re-derived a
  reproduction already public in a PR; nothing here needs to be runnable.

---

## 8. House style for the reports

* **Lead with the answer.** `06-release-gap.md` exists because a reader wants "am I
  exposed, and does upgrading help" before anything else.
* **Rate with CVSS 3.1 and show the vector.** Where the number and the practical risk
  disagree, say which one you would act on and why.
* **Label confidence per finding**: `verified` (reproduced or confirmed in source),
  `confirmed` (source and dependency state checked, exploit not run), `author-reported`.
* **Include non-findings.** A list of things that looked security-relevant and are not makes
  the rest trustworthy. `reports/02` §21 does this.
* **Say what you did not check.** Every report carries a limits section; keep it honest and
  keep it current.
* **Cite the PR, never the vibe.** Every claim should point at a PR number, a file at a ref,
  or a command whose output is quoted.

---

## 9. Before you commit

```sh
python3 - <<'EOF'
import re, os, glob
bad = 0
files = ["README.md"] + glob.glob("reports/**/*.md", recursive=True)
for f in files:
    for m in re.finditer(r"\[([^\]]*)\]\(([^)]+)\)", open(f).read()):
        u = m.group(2).split("#")[0]
        if not u or u.startswith(("http", "mailto")): continue
        if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(f), u))):
            print("MISSING LINK", f, u); bad += 1
    L = open(f).read().split("\n"); i = 0
    while i < len(L):
        if L[i].startswith("|") and i+1 < len(L) and re.match(r"^\|[\s:-]+\|", L[i+1]):
            n = L[i].count("|") - L[i].count("\\|"); j = i+1
            while j < len(L) and L[j].startswith("|"):
                if L[j].count("|") - L[j].count("\\|") != n: print("RAGGED TABLE", f, j+1); bad += 1
                j += 1
            i = j
        else: i += 1
print("issues:", bad)
EOF

git status --short          # data/ must not appear: it is gitignored, ~150 MB
```

Also re-check that the counts agree between `README.md`, `reports/README.md` and
`reports/02` — they were edited at different times and drift easily.
