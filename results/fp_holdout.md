# Phase 2/3 — held-out false-positive measurement

Generated 2026-07-10T19:36:03Z.
Filter corpus A = 78 files; held-out measurement corpus B = 76 files (disjoint).
Rules are generated using A only; FPs below are counted on B, which the rarity
and reduction filters never saw. 95% upper bound is the rule of three for 0 hits.

| Sample | Tier 2 | Tier 2 FP on B | Tier 1 | Tier 1 FP on B | 95% upper bound |
|---|---|---|---|---|---|
| krusty_x | ok | 0 | not earned | — | 3.9% |
| akira_v2_x | ok | 0 | ok | 0 | 3.9% |
| blackcat_sphynx_x | ok | 0 | not earned | — | 3.9% |
| 01flip_x | REFUSED (exit 1) | n/a | n/a | n/a | — |
| p2pinfect_x | REFUSED (exit 1) | n/a | n/a | n/a | — |

## Notes
- "95% upper bound" uses the rule of three (3/n) for 0 observed FPs; it is the
  honest interval a held-out 0/76 implies, not a claim of exactly zero.
- A smaller filter corpus A makes the rarity filter weaker (it sees less benign
  variety), so this is a conservative measurement — the full-corpus filter would
  drop at least as many candidates. Growing corpus/manifest.csv to ~150 and
  splitting 75/75 (both are script runs) tightens the interval further.
