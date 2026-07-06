#!/usr/bin/env bash
# Phase 2 — the measurement. Generates Tier-2 rules for the usable malware
# samples, runs each against the full benign corpus, and records self-fire +
# benign FP count + per-hit diagnosis (which $panic/$code atom matched).
#
# blackcat_x is excluded: it is a Windows PE, not an ELF, and unhusk/Winnow
# are x86-64-ELF-only by design. 01flip_x and p2pinfect_x are expected to
# Tier-0-refuse (see corpus/../findings notes) and are recorded as such
# rather than skipped, because a documented refusal is itself a result.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINNOW="$ROOT/target/release/winnow"
RULES="$ROOT/rules"
CORPUS="$ROOT/corpus/bin"
RESULTS="$ROOT/results"
SAMPLES=/home/user/malware-samples

mkdir -p "$RULES" "$RESULTS"

declare -A SAMPLE_ELF=(
  [krusty_x]="$SAMPLES/krusty_x"
  [akira_v2_x]="$SAMPLES/akira_v2_x"
  [blackcat_sphynx_x]="$SAMPLES/blackcat_sphynx_x"
  [01flip_x]="$SAMPLES/01flip_x"
  [p2pinfect_x]="$SAMPLES/p2pinfect_x"
)

OUT="$RESULTS/fp_table.md"
echo "# Phase 2 — benign false-positive measurement" > "$OUT"
echo "" >> "$OUT"
echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Benign corpus: $(ls "$CORPUS" | wc -l) binaries." >> "$OUT"
echo "" >> "$OUT"
echo "| Sample | Rule generated | Self-fire | Benign FP count | Benign hits (diagnosis) |" >> "$OUT"
echo "|---|---|---|---|---|" >> "$OUT"

for name in "${!SAMPLE_ELF[@]}"; do
  dir="${SAMPLE_ELF[$name]}"
  elf="$(ls "$dir"/*.elf 2>/dev/null | head -1)"
  rule="$RULES/${name}.yar"

  if [[ -z "$elf" ]]; then
    echo "| $name | n/a | n/a | n/a | no .elf in $dir |" >> "$OUT"
    continue
  fi

  gen_out="$("$WINNOW" "$elf" -o "$rule" 2>&1)"
  gen_exit=$?

  if [[ $gen_exit -ne 0 ]]; then
    reason="$(echo "$gen_out" | tr '\n' ' ' | sed 's/|/\\|/g')"
    echo "| $name | REFUSED (exit $gen_exit) | n/a | n/a | $reason |" >> "$OUT"
    continue
  fi

  # Self-fire check.
  if yr scan "$rule" "$elf" >/dev/null 2>&1; then
    self="yes"
  else
    self="**NO — BROKEN**"
  fi

  # Benign corpus scan.
  hits="$(yr scan -r -s "$rule" "$CORPUS" 2>/dev/null)"
  if [[ -z "$hits" ]]; then
    fp_count=0
    diag="none"
  else
    fp_count="$(echo "$hits" | grep -c '^winnow_')"
    # Summarize which atom(s) fired per benign file, for diagnosis.
    diag="$(echo "$hits" | grep -oE '\\\$(panic|code)[0-9]+' | sort | uniq -c | \
      awk '{printf "%s x%s; ", $2, $1}' | sed 's/|/\\|/g')"
    diag_file="$RESULTS/${name}_benign_hits.txt"
    echo "$hits" > "$diag_file"
  fi

  echo "| $name | ok | $self | $fp_count | $diag |" >> "$OUT"
done

echo "" >> "$OUT"
echo "## Diagnostics (never targets, never tuned on)" >> "$OUT"
echo "" >> "$OUT"

# Cross-version diagnostic dropped: blackcat_x is a Windows PE, not usable by
# the ELF-only pipeline, so there is no blackcat_x rule to test against
# blackcat_sphynx_x. See findings notes.
echo "- Cross-version (blackcat_x -> blackcat_sphynx_x): N/A — blackcat_x is a Windows PE," \
  "not an ELF; unhusk/Winnow are x86-64-ELF-only. No rule to test." >> "$OUT"

echo "- 01flip_x (remap-path-prefix case): see main table row above." >> "$OUT"
echo "- p2pinfect_x (claimed legitimately-unpacked): see main table row above." >> "$OUT"

echo ""
echo "Wrote $OUT"
cat "$OUT"
