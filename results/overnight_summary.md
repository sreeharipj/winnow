# Overnight corpus grow — summary

Generated 2026-07-10T19:38:04Z. Corpus grown, then re-measured on the held-out split.

- benign corpus (manifest rows): **75 → 154**
- corpus/bin files: 75 → 158 (includes a few eh_frame-removed diagnostic variants)
- split: A(filter)=78 / B(held-out)=76
- held-out rule-of-three 95% upper bound for 0 FP: **~3.9%** (was ~8.3% at B=36)
- akira still earns the two-factor Tier 1 rule; 0 FP on the 76 held-out benign binaries
- factor-independence: code-only 0/76, string-only 0/76, joint 0/76 (c ≤ a·b/|B| holds)

## Grow-batch build failures (11 of 82 candidates)
Expected tail attrition (missing system libs, workspace bin-name mismatches, flaky
clones). Non-fatal — each success is another held-out benign binary.
```
  b3sum
  diffsitter
  eva
  fastmod
  helix
  huniq
  jless
  mprocs
  rmesg
  uv
  zet
```

See results/fp_holdout.md and results/fp_independence.md for the full tables.
