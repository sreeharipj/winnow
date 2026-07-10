# Phase 3b — factor-independence measurement (held-out corpus B, |B|=36)

Generated 2026-07-10T16:59:55Z.

For each earned Tier 1 rule, the emitted rule (joint) is decomposed into its
two single-factor variants: the other factor's condition clause and its string
defs are dropped (YARA-X rejects unused patterns), so each variant keeps exactly
its own factor's strings, byte-identical to the real rule's. Each is scanned
against the disjoint held-out corpus B. We report the marginals, the joint, and
the product of marginals — the empirical backing for the structural-independence
claim, not an assumed multiplicative bound.

## akira_v2_x

| factor | benign hits on B | marginal FP | 95% upper bound |
|---|---|---|---|
| code-only $mcode*      | 0 | 0/36 | 8.3% |
| string-only $behavior* | 0 | 0/36 | 8.3% |
| joint (emitted rule)   | 0 | 0/36 | 8.3% |

- product of marginals (a/|B|)(b/|B|) = 0.0000; expected-joint-under-independence a·b/|B| = 0.00 hits.
- empirical bound c ≤ a·b/|B|: **holds** (joint 0 ≤ 0.00).

## Notes
- On a corpus where both marginals are 0, the joint is 0 and the product is 0
  too: the value here is the *methodology and the reported table*, which grows
  more informative as the corpus grows (docs/corpus-upgrade.md). What the table
  buys today is turning the C2 independence claim from an asserted product bound
  into a measured fact.
- YARA-X rejects an unused pattern as an error (E022), not a warning, so each
  single-factor variant drops the other factor's string defs too; the strings it
  keeps are byte-identical to the real rule's for that factor. Each variant is
  self-fire-checked against its own sample before its benign count is trusted.
