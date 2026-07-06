# Phase 2 — benign false-positive measurement

Generated 2026-07-06T09:28:33Z. Benign corpus: 75 binaries.

| Sample | Rule generated | Self-fire | Benign FP count | Benign hits (diagnosis) |
|---|---|---|---|---|
| blackcat_sphynx_x | ok | yes | 0 | none |
| akira_v2_x | ok | yes | 0 | none |
| 01flip_x | REFUSED (exit 1) | n/a | n/a | winnow: TIER 0 REFUSE — no STRONG-tier author functions in /home/user/malware-samples/01flip_x/e5834b7bdd70ec904470d541713e38fe933e96a4e49f80dbfb25148d9674f957.elf         (packed binary, aggressive path remapping, or no reachable user panic evidence)  |
| p2pinfect_x | REFUSED (exit 1) | n/a | n/a | winnow: TIER 0 REFUSE — no STRONG-tier author functions in /home/user/malware-samples/p2pinfect_x/3a43116d507d58f3c9717f2cb0a3d06d0c5a7dc29f601e9c2b976ee6d9c8713f.elf         (packed binary, aggressive path remapping, or no reachable user panic evidence)  |
| krusty_x | ok | yes | 0 | none |

## Diagnostics (never targets, never tuned on)

- Cross-version (blackcat_x -> blackcat_sphynx_x): N/A — blackcat_x is a Windows PE, not an ELF; unhusk/Winnow are x86-64-ELF-only. No rule to test.
- 01flip_x (remap-path-prefix case): see main table row above.
- p2pinfect_x (claimed legitimately-unpacked): see main table row above.
