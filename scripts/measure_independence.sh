#!/usr/bin/env bash
# Phase 3b — factor-independence measurement (see docs/fp-independence-measurement.md).
#
# The Tier 1 flagship rule is `... and any of ($mcode*) and any of ($behavior*)`:
# a masked-code factor AND an independent behavioral-string factor, required to
# come from disjoint author functions. Structural disjointness guarantees the
# rule is *genuinely two factors* (not one function wearing two hats) — it does
# NOT, by itself, prove the two benign match events are statistically
# independent. So we do not assert P(A∩B)=P(A)P(B); we MEASURE it.
#
# For each EARNED Tier 1 rule this script derives two single-factor variants.
# YARA-X rejects an unused pattern as an ERROR (E022), not a warning, so each
# variant drops the OTHER factor's condition clause AND its string defs; the
# strings each variant keeps are byte-identical to the real rule's for that
# factor, which is the faithfulness the measurement needs:
#
#   code-only   :  ... and any of ($mcode*)     ($mcode* defs only)
#   string-only :  ... and any of ($behavior*)  ($behavior* defs only)
#   joint       :  the emitted rule (both), already measured by measure_holdout
#
# All three are scanned against the held-out corpus B. We report each marginal
# FP, the joint FP, and the product of marginals — a measured table, not an
# assumed bound. winnow is untouched; this is a pure post-processing transform.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINNOW="$ROOT/target/release/winnow"
RULES="$ROOT/rules"
RESULTS="$ROOT/results"
A="$ROOT/corpus/split_a"
B="$ROOT/corpus/split_b"
SAMPLES=/home/user/malware-samples

mkdir -p "$RULES" "$RESULTS"

# Reproduce the same deterministic A/B split the held-out harness uses.
bash "$ROOT/scripts/split_corpus.sh"
NB=$(ls "$B" | wc -l)

declare -A SAMPLE_ELF=(
  [krusty_x]="$SAMPLES/krusty_x"
  [akira_v2_x]="$SAMPLES/akira_v2_x"
  [blackcat_sphynx_x]="$SAMPLES/blackcat_sphynx_x"
  [01flip_x]="$SAMPLES/01flip_x"
  [p2pinfect_x]="$SAMPLES/p2pinfect_x"
)

OUT="$RESULTS/fp_independence.md"

# 95% upper bound on a proportion: rule of three (3/n) for 0 hits, else (k+2)/n.
ub_pct() { awk -v k="$1" -v n="$2" 'BEGIN{ if(n==0){print "n/a"} else {printf "%.1f%%", (k==0? 3.0/n : (k+2.0)/n)*100} }'; }
# count '^winnow' rule-match lines from a yr scan (stdout only; stderr may carry
# the harmless "unused string" warning the single-factor variants trigger).
scan_hits() { yr scan -r "$1" "$B" 2>/dev/null | grep -c '^winnow' || true; }

{
  echo "# Phase 3b — factor-independence measurement (held-out corpus B, |B|=${NB})"
  echo ""
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)."
  echo ""
  echo "For each earned Tier 1 rule, the emitted rule (joint) is decomposed into its"
  echo "two single-factor variants: the other factor's condition clause and its string"
  echo "defs are dropped (YARA-X rejects unused patterns), so each variant keeps exactly"
  echo "its own factor's strings, byte-identical to the real rule's. Each is scanned"
  echo "against the disjoint held-out corpus B. We report the marginals, the joint, and"
  echo "the product of marginals — the empirical backing for the structural-independence"
  echo "claim, not an assumed multiplicative bound."
  echo ""
} > "$OUT"

earned_any=0

for name in krusty_x akira_v2_x blackcat_sphynx_x 01flip_x p2pinfect_x; do
  dir="${SAMPLE_ELF[$name]}"
  elf="$(ls "$dir"/*.elf 2>/dev/null | head -1)"
  [[ -z "$elf" ]] && continue

  t2="$RULES/${name}.yar"
  t1="$RULES/${name}_tier1.yar"
  rm -f "$t2" "$t1"

  # Regenerate against A only, exactly as the held-out harness does.
  "$WINNOW" "$elf" --tier1 --corpus-dir "$A" -o "$t2" --tier1-output "$t1" >/dev/null 2>&1 || true

  # Only earned (Tier 1 emitted) samples have a factor decomposition to measure.
  [[ -f "$t1" ]] || continue
  earned_any=1

  code_only="$RULES/${name}_tier1_codeonly.yar"
  str_only="$RULES/${name}_tier1_stringonly.yar"
  # YARA-X rejects an unused pattern (E022 is an error, not a warning), so each
  # single-factor variant drops the OTHER factor's string defs as well as its
  # condition clause. The strings each variant keeps are byte-identical to the
  # real rule's for that factor — the faithfulness the measurement needs.
  sed -e '/^[[:space:]]*\$behavior[0-9]/d' -e 's/ and any of (\$behavior\*)//' "$t1" > "$code_only"
  sed -e '/^[[:space:]]*\$mcode[0-9]/d'    -e 's/any of (\$mcode\*) and //'    "$t1" > "$str_only"

  # Self-fire guard: a variant that does not match its own sample is broken
  # (compile error, bad edit) and its benign 0 would be a false zero. Assert
  # each variant fires on the malware before trusting its count on B.
  for v in "$code_only" "$str_only" "$t1"; do
    if [[ "$(yr scan "$v" "$elf" 2>/dev/null | grep -c '^winnow')" -lt 1 ]]; then
      echo "measure_independence: FATAL $(basename "$v") does not self-fire on $name" >&2
      yr scan "$v" "$elf" 2>&1 | sed 's/^/  /' >&2
      exit 3
    fi
  done

  a="$(scan_hits "$code_only")"   # code-only marginal
  b="$(scan_hits "$str_only")"    # string-only marginal
  c="$(scan_hits "$t1")"          # joint (emitted rule)

  # product of marginals and the empirical inequality c <= a*b/NB
  prod="$(awk -v a="$a" -v b="$b" -v n="$NB" 'BEGIN{ if(n==0){print "n/a"} else printf "%.4f", (a/n)*(b/n) }')"
  abn="$(awk -v a="$a" -v b="$b" -v n="$NB" 'BEGIN{ if(n==0){print "n/a"} else printf "%.2f", (a*b)/n }')"
  ineq="$(awk -v c="$c" -v a="$a" -v b="$b" -v n="$NB" 'BEGIN{ print (c <= (a*b)/n) ? "holds" : "VIOLATED" }')"

  {
    echo "## $name"
    echo ""
    echo "| factor | benign hits on B | marginal FP | 95% upper bound |"
    echo "|---|---|---|---|"
    echo "| code-only \$mcode*      | $a | $a/$NB | $(ub_pct "$a" "$NB") |"
    echo "| string-only \$behavior* | $b | $b/$NB | $(ub_pct "$b" "$NB") |"
    echo "| joint (emitted rule)   | $c | $c/$NB | $(ub_pct "$c" "$NB") |"
    echo ""
    echo "- product of marginals (a/|B|)(b/|B|) = $prod; expected-joint-under-independence a·b/|B| = $abn hits."
    echo "- empirical bound c ≤ a·b/|B|: **$ineq** (joint $c ≤ $abn)."
    echo ""
  } >> "$OUT"

  rm -f "$code_only" "$str_only"
done

if [[ "$earned_any" == "0" ]]; then
  echo "_No sample earned a Tier 1 rule against corpus A; nothing to decompose._" >> "$OUT"
fi

{
  echo "## Notes"
  echo "- On a corpus where both marginals are 0, the joint is 0 and the product is 0"
  echo "  too: the value here is the *methodology and the reported table*, which grows"
  echo "  more informative as the corpus grows (docs/corpus-upgrade.md). What the table"
  echo "  buys today is turning the C2 independence claim from an asserted product bound"
  echo "  into a measured fact."
  echo "- YARA-X rejects an unused pattern as an error (E022), not a warning, so each"
  echo "  single-factor variant drops the other factor's string defs too; the strings it"
  echo "  keeps are byte-identical to the real rule's for that factor. Each variant is"
  echo "  self-fire-checked against its own sample before its benign count is trusted."
} >> "$OUT"

echo ""
echo "Wrote $OUT"
cat "$OUT"
