#!/usr/bin/env bash
# Overnight, unattended: grow the benign corpus, then re-measure on it.
#
#   1. build the grow-batch slice of build_corpus.sh (hard-capped in wall time)
#   2. merge the new binaries' manifest rows into corpus/manifest.csv (dedup by
#      name; existing rows win)
#   3. re-run the held-out FP measurement AND the factor-independence measurement
#      on the enlarged corpus (both recompute the A/B split themselves)
#   4. write results/overnight_summary.md
#
# It does NOT git-commit — everything is left in-tree for review. Safe overnight
# defaults are set here if the env doesn't override them: single build at a time
# (PBUILD=1) so only one heavy link runs at once on a RAM-tight host, a 40-min
# per-crate cap, and a 6-hour cap on the whole build phase.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG="$ROOT/corpus/overnight.log"
SUMMARY="$ROOT/results/overnight_summary.md"
MANIFEST="$ROOT/corpus/manifest.csv"

export PBUILD="${PBUILD:-1}"
export JOBS="${JOBS:-8}"
export BUILD_TIMEOUT="${BUILD_TIMEOUT:-2400}"
GROW_START="${GROW_START:-77}"
GROW_DEADLINE_SECS="${GROW_DEADLINE_SECS:-21600}"

exec > >(tee -a "$LOG") 2>&1
echo "=== overnight_grow START $(date -u +%FT%TZ) | PBUILD=$PBUILD JOBS=$JOBS BUILD_TIMEOUT=${BUILD_TIMEOUT}s deadline=${GROW_DEADLINE_SECS}s ==="

# Hold an idle-suspend inhibitor for the life of this run (idle-suspend killed an
# earlier run). Use a BACKGROUNDED lock, not a re-exec: re-exec'ing under
# systemd-inhibit detaches this process from the parent's tracking so the run
# becomes invisible/untracked. The backgrounded lock keeps THIS pid the tracked
# one. The lock is released by the EXIT trap when the run ends.
INHIBIT_PID=""
if command -v systemd-inhibit >/dev/null 2>&1; then
  systemd-inhibit --what=sleep:idle --who=winnow --why="winnow overnight corpus grow" \
    --mode=block sleep "$GROW_DEADLINE_SECS" &
  INHIBIT_PID=$!
  trap '[[ -n "$INHIBIT_PID" ]] && kill "$INHIBIT_PID" 2>/dev/null' EXIT
  echo "overnight_grow: holding sleep:idle inhibitor (pid $INHIBIT_PID) for the run"
else
  echo "overnight_grow: systemd-inhibit unavailable; no suspend guard"
fi

before_bins=$(ls "$ROOT/corpus/bin" 2>/dev/null | wc -l)
before_rows=$(tail -n +2 "$MANIFEST" | wc -l)
echo "before: corpus/bin=$before_bins manifest_rows=$before_rows"

# --- 1. build phase, hard-capped so a wedged build can't eat the whole night ---
timeout -k 60 "$GROW_DEADLINE_SECS" bash "$ROOT/scripts/build_corpus.sh" "$GROW_START"
bstat=$?
if [[ $bstat -eq 124 ]]; then bnote="hit ${GROW_DEADLINE_SECS}s deadline"; else bnote="finished (exit $bstat)"; fi
echo "=== build phase $bnote $(date -u +%FT%TZ) ==="

# --- 2. merge new manifest shard(s) into manifest.csv (dedup by name; keep existing) ---
merged=0
for shard in "$MANIFEST".${GROW_START}-* ; do
  [[ -f "$shard" ]] || continue
  echo "merging shard: $shard ($(tail -n +2 "$shard" | wc -l) rows)"
  tmp="$(mktemp)"
  head -1 "$MANIFEST" > "$tmp"
  { tail -n +2 "$MANIFEST"; tail -n +2 "$shard"; } | awk -F, 'NF>=5 && !seen[$1]++' >> "$tmp"
  mv "$tmp" "$MANIFEST"
  merged=1
done
[[ $merged -eq 0 ]] && echo "WARN: no manifest shard found for start=$GROW_START"

after_bins=$(ls "$ROOT/corpus/bin" 2>/dev/null | wc -l)
after_rows=$(tail -n +2 "$MANIFEST" | wc -l)
echo "after:  corpus/bin=$after_bins manifest_rows=$after_rows (+$((after_rows-before_rows)) rows)"

# --- 3. re-measure on the enlarged corpus (each script recomputes the split) ---
echo "=== re-measure: measure_holdout.sh $(date -u +%FT%TZ) ==="
bash "$ROOT/scripts/measure_holdout.sh" >/dev/null 2>&1; hstat=$?
echo "measure_holdout exit=$hstat"
echo "=== re-measure: measure_independence.sh $(date -u +%FT%TZ) ==="
bash "$ROOT/scripts/measure_independence.sh" >/dev/null 2>&1; istat=$?
echo "measure_independence exit=$istat (3 = a variant failed self-fire — investigate)"

NB=$(ls "$ROOT/corpus/split_b" 2>/dev/null | wc -l)
NA=$(ls "$ROOT/corpus/split_a" 2>/dev/null | wc -l)
ub=$(awk -v n="$NB" 'BEGIN{ if(n==0)print "n/a"; else printf "%.1f%%", 300.0/n }')

# --- 4. summary ---
{
  echo "# Overnight corpus grow — summary"
  echo ""
  echo "Generated $(date -u +%FT%TZ)."
  echo ""
  echo "- corpus/bin: **$before_bins → $after_bins** (+$((after_bins-before_bins)) binaries)"
  echo "- manifest rows: $before_rows → $after_rows"
  echo "- split: A(filter)=$NA / B(held-out)=$NB"
  echo "- held-out rule-of-three 95% upper bound for 0 FP: **~$ub** (was ~8.3% at B=36)"
  echo "- build phase: $bnote"
  echo "- measure_holdout exit=$hstat ; measure_independence exit=$istat"
  echo ""
  echo "## Build failures (grow batch)"
  echo '```'
  # Only real failure markers -- the faillog also captures cargo's normal stderr
  # (Compiling..., Blocking waiting for file lock), which are not failures.
  grep -hE 'CLONE FAILED|BUILD FAILED|BINARY NOT FOUND|SKIPPED \(low disk' \
    "$ROOT/corpus/build_failures.log.${GROW_START}-"* 2>/dev/null | sort -u | sed 's/^/  /' \
    || echo "  (none)"
  echo '```'
  echo ""
  echo "## results/fp_holdout.md"
  echo '```'
  cat "$ROOT/results/fp_holdout.md" 2>/dev/null
  echo '```'
  echo ""
  echo "## results/fp_independence.md"
  echo '```'
  cat "$ROOT/results/fp_independence.md" 2>/dev/null
  echo '```'
  echo ""
  echo "_Not committed. Review, then commit corpus/manifest.csv + results/*._"
} > "$SUMMARY"

echo "=== overnight_grow DONE $(date -u +%FT%TZ). Summary: $SUMMARY ==="
echo "corpus/bin $before_bins -> $after_bins ; B=$NB ; upper bound ~$ub"