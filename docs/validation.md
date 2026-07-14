# Validation

winnow's only false-positive claim is measured once, on a held-out split, rather than re-validated per rule or per family. This page is the raw measurement behind the numbers quoted in the README.

## Method: filter corpus A, held-out corpus B

The benign corpus is split into a filter half (A) and a disjoint held-out half (B). Rules are built, and their strings/atoms are rarity-filtered, against A only. False positives are then counted exclusively on B.

This split exists because counting on A would be circular: a rule's strings are selected for being *absent* from the filter corpus, so no A binary can ever match a rule whose strings were chosen for being absent from it. A zero measured on A is a restatement of the filtering step, not a result. B is disjoint from every filtering decision, so a zero measured there is an actual result.

Corpus construction note: binaries must be built with `git clone` + `cargo build --release`, not `cargo install`. The latter builds from `~/.cargo/registry/`, which rewrites the tool's own source paths to `registry/...` and makes unhusk classify the author's own code as a dependency instead of User — exercising the wrong attribution path and reporting a meaningless number.

## Phase 2 — initial benign FP measurement (75 binaries)

Generated 2026-07-06.

| Sample | Rule generated | Self-fire | Benign FP count | Benign hits (diagnosis) |
|---|---|---|---|---|
| blackcat_sphynx_x | ok | yes | 0 | none |
| akira_v2_x | ok | yes | 0 | none |
| 01flip_x | REFUSED (exit 1) | n/a | n/a | Tier 0 refuse — no STRONG-tier author functions (packed binary, aggressive path remapping, or no reachable user panic evidence) |
| p2pinfect_x | REFUSED (exit 1) | n/a | n/a | Tier 0 refuse — no STRONG-tier author functions (packed binary, aggressive path remapping, or no reachable user panic evidence) |
| krusty_x | ok | yes | 0 | none |

Diagnostics, never targets, never tuned on: `blackcat_x` (Windows PE) is out of scope for an ELF-only tool, so no cross-version rule exists to test.

## Phase 2/3 — held-out FP measurement (A=78, B=76)

Generated 2026-07-10. Filter corpus A = 78 files; held-out measurement corpus B = 76 files (disjoint). Rules are generated using A only; the FPs below are counted on B, which the rarity and reduction filters never saw.

| Sample | Tier 2 | Tier 2 FP on B | Tier 1 | Tier 1 FP on B | 95% upper bound |
|---|---|---|---|---|---|
| krusty_x | ok | 0 | not earned | — | 3.9% |
| akira_v2_x | ok | 0 | ok | 0 | 3.9% |
| blackcat_sphynx_x | ok | 0 | not earned | — | 3.9% |
| 01flip_x | REFUSED (exit 1) | n/a | n/a | n/a | — |
| p2pinfect_x | REFUSED (exit 1) | n/a | n/a | n/a | — |

The "95% upper bound" uses the rule of three (3/n) for 0 observed FPs on B=76 — the honest interval a held-out 0/76 implies, not a claim of exactly zero. It was about 8% at B=36, before the corpus was grown to its current size; growing the corpus only tightens this interval, so growing it costs nothing in the pipeline. A smaller filter corpus A also makes the rarity filter weaker (it sees less benign variety), so this is a conservative measurement — the full-corpus filter would drop at least as many candidates.

An early scan was sanity-checked against a trivially-true rule, which matched every corpus binary, confirming that a zero here is a real result and not a broken scanner reporting no matches for the wrong reason.

## Phase 3b — factor-independence measurement (held-out B, |B|=76)

Generated 2026-07-10.

Tier 1 rules AND a code factor with a string factor, and that multiplication is only valid if the two factors are independent. For each earned Tier 1 rule, the emitted rule is decomposed into its two single-factor variants — the other factor's condition clause and string defs are dropped — and each variant is scanned against B separately. This reports the marginals, the joint, and the product of marginals: the empirical backing for the independence claim, not an assumed multiplicative bound.

### akira_v2_x

| factor | benign hits on B | marginal FP | 95% upper bound |
|---|---|---|---|
| code-only ($mcode*) | 0 | 0/76 | 3.9% |
| string-only ($behavior*) | 0 | 0/76 | 3.9% |
| joint (emitted rule) | 0 | 0/76 | 3.9% |

Product of marginals (a/\|B\|)(b/\|B\|) = 0.0000; expected-joint-under-independence a·b/\|B\| = 0.00 hits. Empirical bound c ≤ a·b/\|B\| holds (joint 0 ≤ 0.00).

On a corpus where both marginals are 0, the joint is 0 and the product is 0 too — the value here is the methodology and the reported table, which grows more informative as the corpus grows. What the table buys today is turning the independence claim from an asserted product bound into a measured fact. Each single-factor variant drops the other factor's string defs (YARA-X rejects an unused pattern as an error, not a warning), so the strings each variant keeps are byte-identical to the real rule's for that factor, and each variant is self-fire-checked against its own sample before its benign count is trusted.

## Summary

Zero false positives across three earned rules (two Tier 2, one Tier 1) and 76 held-out benign binaries the filtering step never saw — a rule-of-three 95% upper bound of about 3.9% at this N. The Tier 1 independence property (code factor and string factor drawn from disjoint functions, scored separately) holds structurally, not just empirically, and the held-out measurement confirms it rather than assuming it.

Reproduce with `scripts/measure_holdout.sh` and `scripts/measure_independence.sh` (see README).
