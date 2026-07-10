#!/usr/bin/env bash
# Deterministic, category-stratified split of the benign corpus into a filter
# set (A) and a held-out false-positive measurement set (B).
#
# Why this exists: rarity filtering and masked-atom reduction *select* Tier 1
# ingredients by their absence from the corpus. Measuring false positives on
# that same corpus is circular — zero FPs is then a theorem, not a measurement
# (see the commit that introduced this concern). So we filter against A only
# and measure against B, which the filters never see.
#
# The split is category-stratified: within each manifest category we sort by
# name and alternate A/B, so both halves carry the same async/cli/parallel mix
# and neither is accidentally e.g. all-async. It is deterministic (pure sort),
# so re-running reproduces the identical partition.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/corpus/bin"
MAN="$ROOT/corpus/manifest.csv"
A="$ROOT/corpus/split_a"
B="$ROOT/corpus/split_b"

rm -rf "$A" "$B"
mkdir -p "$A" "$B"

# manifest columns: name,git_url,commit_sha,bin_name,category,...
tail -n +2 "$MAN" | sort -t, -k5,5 -k1,1 | awk -F, '
  { cat=$5; name=$1; n[cat]++; side=(n[cat]%2==1)?"a":"b"; print name, side }
' | while read -r name side; do
  if [[ ! -f "$BIN/$name" ]]; then
    echo "split_corpus: WARN manifest entry '$name' has no binary in corpus/bin, skipping" >&2
    continue
  fi
  if [[ "$side" == "a" ]]; then
    ln -sf "../bin/$name" "$A/$name"
  else
    ln -sf "../bin/$name" "$B/$name"
  fi
done

echo "split_corpus: A (filter) = $(ls "$A" | wc -l) files, B (held-out FP) = $(ls "$B" | wc -l) files"
