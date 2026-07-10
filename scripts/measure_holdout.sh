#!/usr/bin/env bash
# Phase 2/3 measurement, done honestly on held-out data.
#
# The original measure.sh filtered Tier 1 ingredients against the full benign
# corpus and then measured false positives against that same corpus — circular:
# no corpus binary *can* match a rule whose strings were chosen for being absent
# from it. This script instead:
#
#   1. splits the corpus into A (filter) and B (held out) — scripts/split_corpus.sh
#   2. generates each rule with --corpus-dir A only
#   3. measures false positives on B, which the filters never saw
#   4. reports the count AND a rule-of-three 95% upper bound, because 0/36 is
#      an interval (upper bound ~8%), not a point at zero.
#
# It (re)writes results/tier1_report.md (the generation narrative) and
# results/fp_holdout.md (the held-out FP measurement).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINNOW="$ROOT/target/release/winnow"
RULES="$ROOT/rules"
RESULTS="$ROOT/results"
A="$ROOT/corpus/split_a"
B="$ROOT/corpus/split_b"
SAMPLES=/home/user/malware-samples

mkdir -p "$RULES" "$RESULTS"

bash "$ROOT/scripts/split_corpus.sh"
NA=$(ls "$A" | wc -l)
NB=$(ls "$B" | wc -l)

declare -A SAMPLE_ELF=(
  [krusty_x]="$SAMPLES/krusty_x"
  [akira_v2_x]="$SAMPLES/akira_v2_x"
  [blackcat_sphynx_x]="$SAMPLES/blackcat_sphynx_x"
  [01flip_x]="$SAMPLES/01flip_x"
  [p2pinfect_x]="$SAMPLES/p2pinfect_x"
)

FP="$RESULTS/fp_holdout.md"
TIER1="$RESULTS/tier1_report.md"

# 95% upper bound on a proportion when k successes are seen in n trials.
# For k=0 this is the rule of three (~3/n). For k>0 we report the point rate
# and a rough (k+2)/n upper marker; small-n exactness is not the point here.
ub_pct() { # args: k n
  awk -v k="$1" -v n="$2" 'BEGIN{ if(n==0){print "n/a"} else {printf "%.1f%%", (k==0? 3.0/n : (k+2.0)/n)*100} }'
}

{
  echo "# Phase 3 — Tier 1 flagship attempt (filter corpus = held-out split A, ${NA} files)"
  echo ""
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Rules are built against Corpus A only;"
  echo "false positives are measured on the disjoint Corpus B (see results/fp_holdout.md)."
  echo ""
} > "$TIER1"

{
  echo "# Phase 2/3 — held-out false-positive measurement"
  echo ""
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)."
  echo "Filter corpus A = ${NA} files; held-out measurement corpus B = ${NB} files (disjoint)."
  echo "Rules are generated using A only; FPs below are counted on B, which the rarity"
  echo "and reduction filters never saw. 95% upper bound is the rule of three for 0 hits."
  echo ""
  echo "| Sample | Tier 2 | Tier 2 FP on B | Tier 1 | Tier 1 FP on B | 95% upper bound |"
  echo "|---|---|---|---|---|---|"
} > "$FP"

for name in krusty_x akira_v2_x blackcat_sphynx_x 01flip_x p2pinfect_x; do
  dir="${SAMPLE_ELF[$name]}"
  elf="$(ls "$dir"/*.elf 2>/dev/null | head -1)"
  t2="$RULES/${name}.yar"
  t1="$RULES/${name}_tier1.yar"
  rm -f "$t2" "$t1"

  if [[ -z "$elf" ]]; then
    echo "| $name | n/a | n/a | n/a | n/a | — | (no .elf)" >> "$FP"
    continue
  fi

  gen="$("$WINNOW" "$elf" --tier1 --corpus-dir "$A" -o "$t2" --tier1-output "$t1" 2>&1)"
  gen_exit=$?

  {
    echo "## $name"
    echo '```'
    echo "$gen" | sed 's/^winnow: //'
    echo '```'
    echo ""
  } >> "$TIER1"

  if [[ $gen_exit -ne 0 ]]; then
    reason="$(echo "$gen" | tr '\n' ' ' | sed 's/|/\\|/g')"
    echo "| $name | REFUSED (exit $gen_exit) | n/a | n/a | n/a | — |" >> "$FP"
    continue
  fi

  # Tier 2 FP on B.
  t2_fp=0
  if [[ -f "$t2" ]]; then
    t2_fp="$(yr scan -r "$t2" "$B" 2>/dev/null | grep -c '^winnow' || true)"
  fi

  # Tier 1 FP on B (only if the flagship was earned/emitted).
  if [[ -f "$t1" ]]; then
    t1_present="ok"
    t1_fp="$(yr scan -r "$t1" "$B" 2>/dev/null | grep -c '^winnow' || true)"
    ub="$(ub_pct "$t1_fp" "$NB")"
  else
    t1_present="not earned"
    t1_fp="—"
    ub="$(ub_pct "$t2_fp" "$NB")"
  fi

  echo "| $name | ok | $t2_fp | $t1_present | $t1_fp | $ub |" >> "$FP"
done

{
  echo ""
  echo "## Notes"
  echo "- \"95% upper bound\" uses the rule of three (3/n) for 0 observed FPs; it is the"
  echo "  honest interval a held-out 0/${NB} implies, not a claim of exactly zero."
  echo "- A smaller filter corpus A makes the rarity filter weaker (it sees less benign"
  echo "  variety), so this is a conservative measurement — the full-corpus filter would"
  echo "  drop at least as many candidates. Growing corpus/manifest.csv to ~150 and"
  echo "  splitting 75/75 (both are script runs) tightens the interval further."
} >> "$FP"

echo ""
echo "Wrote $TIER1 and $FP"
cat "$FP"
