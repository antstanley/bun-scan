#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p data/sec
nums=$(python3 -c "
import json
p=json.load(open('data/prs_classified.json'))
print(' '.join(str(x['number']) for x in p if x['security_tier']))
")
for n in $nums; do
  out="data/sec/$n.json"
  [ -s "$out" ] && continue
  gh api "repos/oven-sh/bun/pulls/$n" > "$out" 2>/dev/null || echo "fail $n"
done
echo "collected $(ls data/sec | wc -l | tr -d ' ')"
