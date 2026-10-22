#!/usr/bin/env bash
# Fetch every PR merged into main since the last release tag.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p data/next/pr
nums=$(python3 -c "import json;print(' '.join(str(n) for n in json.load(open('data/next/index.json'))['prs']))")
for n in $nums; do
  out="data/next/pr/$n.json"
  [ -s "$out" ] && continue
  gh api "repos/oven-sh/bun/pulls/$n" > "$out" 2>/dev/null || { echo "fail $n"; rm -f "$out"; }
done
echo "collected $(ls data/next/pr | wc -l | tr -d ' ')"
