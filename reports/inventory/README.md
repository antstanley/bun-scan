# PR inventory

Every open pull request on `oven-sh/bun`, one row each, grouped by what the PR is for.

| File | PRs |
|---|---|
| [01-security.md](01-security.md) | 38 |
| [02-features.md](02-features.md) | 380 |
| [03-performance.md](03-performance.md) | 53 |
| [04-fixes-part1.md](04-fixes-part1.md) | 1100 |
| [04-fixes-part2.md](04-fixes-part2.md) | 1100 |
| [04-fixes-part3.md](04-fixes-part3.md) | 1100 |
| [04-fixes-part4.md](04-fixes-part4.md) | 1086 |
| [05-tests.md](05-tests.md) | 430 |
| [06-docs.md](06-docs.md) | 184 |
| [07-chores-refactors-other.md](07-chores-refactors-other.md) | 181 |

The machine-readable version of the same data is [`../prs.csv`](../prs.csv).

## Columns

- **Title** — the PR title, trimmed.
- **What it does** — the first lines of the PR's own `What`/`Problem`/`Summary` section, cleaned of markdown and cut to about 150 characters. For most PRs this is the author's own description, not my paraphrase.
- **Sec** — the security tier, for the ~4% of PRs that have one (see `../03-security-triage.md`).
- **draft** — the PR is marked as a draft.
