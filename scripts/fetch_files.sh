#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p data/files
for n in "$@"; do
  out="data/files/$n.json"
  [ -s "$out" ] && { echo "$n cached"; continue; }
  if gh api "repos/oven-sh/bun/pulls/$n/files?per_page=100" > "$out" 2>/dev/null; then
    echo "$n: $(jq 'length' "$out") files, +$(jq '[.[].additions]|add' "$out")/-$(jq '[.[].deletions]|add' "$out")"
  else
    echo "$n: FAILED"; rm -f "$out"
  fi
done
