#!/usr/bin/env bash
# Fetch all open PRs for oven-sh/bun, compacted to the fields we analyze.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p data/pages data/tmp

PER_PAGE=100
PAGES=${PAGES:-60}
START=${START:-1}

for p in $(seq "$START" "$PAGES"); do
  out="data/pages/page_$(printf '%04d' "$p").json"
  if [ -s "$out" ]; then
    echo "page $p: cached"
    continue
  fi
  tmp="data/tmp/page_$(printf '%04d' "$p").raw.json"
  if ! gh api "repos/oven-sh/bun/pulls?state=open&per_page=${PER_PAGE}&page=${p}" > "$tmp" 2>"data/tmp/err_$p.txt"; then
    echo "page $p: FETCH FAILED: $(cat "data/tmp/err_$p.txt")"
    rm -f "$tmp"
    sleep 3
    continue
  fi
  n=$(jq 'length' "$tmp" 2>/dev/null || echo 0)
  jq '[.[] | {
        number,
        title,
        user: .user.login,
        author_association,
        created_at,
        updated_at,
        url: .html_url,
        draft,
        state,
        labels: [.labels[]?.name],
        body: .body,
        additions,
        deletions,
        changed_files,
        comments,
        review_comments,
        commits,
        base: .base.ref,
        head: .head.ref,
        head_sha: .head.sha,
        maintainer_can_modify,
        milestone: .milestone.title
      }]' "$tmp" > "$out"
  rm -f "$tmp"
  echo "page $p: $n PRs"
  if [ "$n" -lt "$PER_PAGE" ]; then
    echo "reached last page at $p"
    break
  fi
done
