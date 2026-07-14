# winnow

Generates a YARA-X rule for a stripped x86-64 Rust malware binary. One binary in, one rule for that binary out. Built on [unhusk](https://github.com/sreeharipj/unhusk), which isolates the author-written functions in a stripped Rust binary from panic metadata.

unhusk answers "which bytes in this stripped Rust binary are the author's." winnow turns that answer into a signature. Because unhusk's inputs are attributed to the author by construction — panic-metadata provenance, not a heuristic — the bytes and strings winnow builds a rule from are the author's own, not stdlib and not dependency crates. A rule built only from author-unique material should not fire on unrelated software; that claim is measured, not assumed (zero false positives across three rules on a 76-binary held-out corpus — see [`docs/validation.md`](docs/validation.md)).

## Install

```sh
cargo build --release      # Rust 1.70+
```

winnow shells out to `unhusk`, which must be on `PATH` (or passed via `--unhusk-bin <path>`); see the [unhusk](https://github.com/sreeharipj/unhusk) repo to build it.

## Usage

```sh
# Tier 2 (workhorse): generate a YARA-X rule for a stripped Rust malware binary
winnow <stripped-elf>                     # emits <name>.yar

# Also attempt Tier 1 (masked-hex + independent behavioral string), gated on
# the benign corpus this project measured itself against:
winnow <stripped-elf> --tier1 --corpus-dir corpus/bin
                                           # emits <name>.yar and, only if
                                           # earned, <name>_tier1.yar
```

## Example output

Run against a real Akira ransomware sample with `--tier1`:

```
wrote akira_v2_x.yar (7 STRONG fns, 4 panic strings, 21 code atoms)
tier1 — measuring against benign corpus (78 files)
tier1 — masked atom for fn 0xc805c reduced 186B -> 64B window at +0x2b (64 exact bytes, 0 corpus collisions)
tier1 — behavioral string "/tmp/stop_vms.sh" (fn 0xdc434) is rare — kept
tier1 — code factor: 7 atom(s) reduced & kept, 0 dropped as non-discriminative
wrote akira_v2_x_tier1.yar
```

The rule it wrote: [`examples/akira_v2_x_tier1.yar`](examples/akira_v2_x_tier1.yar) — a real Tier 1 rule, masked code atoms and independent behavioral strings drawn from disjoint functions, unmodified from what the tool produced.

## One binary, one rule (the design, not a shortcut)

winnow does not generalize across a malware family or across versions. One sample produces one rule that fingerprints that sample. If the rule also catches a later build because the author never touched the fingerprinted functions, that is a free hit — never a target, never something a rule is loosened to achieve.

This is the whole false-positive strategy. Generalization is where false positives come from: every step a signature takes toward matching a family is a step toward matching something benign. winnow starts from material guaranteed unique to one author and its only job is to keep that uniqueness intact all the way to the rule. Chasing the next version would trade a real present guarantee for a speculative future hit, so it doesn't.

## Measurement gates construction

The governing rule of the project: no component ships before the experiment that would falsify its reason to exist has run.

The design claim — near-zero false positives from author-unique inputs — is an argument, and the argument has a hole. "This string is rare," "this pattern won't collide," "these bytes are discriminative" are all claims about a background distribution of benign code. You cannot know a string is rare without a model of what is common, and that model is a benign corpus. So the honest claim is not "no benign corpus needed." It is **no per-family validation**: the benign false-positive rate is measured once, and per-rule specificity thereafter rests on author-attribution, not on re-validating each family against negative data. Every phase is ordered to produce that measurement early and let it decide what gets built next.

## The benign corpus

154 benign x86-64 ELF Rust binaries, release-built and stripped, spanning CLI, systems, async, and parallel tools — the shapes the malware set also takes. A subset had `.eh_frame` removed to mirror the boundary-degraded regime. It began at 75 and was grown to 154; the only thing that growth buys is a tighter false-positive interval, so it costs nothing in the pipeline to keep growing it.

The corpus is split into a filter half (A) and a disjoint held-out half (B). Rules are built against A, and their false positives are counted only on B — see [`docs/validation.md`](docs/validation.md) for why that split matters and for the full measurement.

## Tiers

winnow emits the strongest rule its evidence supports and stamps each rule with what it rests on. The evidence is not uniformly available — inherited from unhusk, panic strings survive far more stripping than function boundaries do — so the generator degrades rather than failing shut.

- **Tier 1, multi-factor.** Masked-hex from STRONG author functions AND an independent behavioral string. The strongest rule; requires the coincidence of author-unique code and author-unique data that do not co-vary.
- **Tier 2, strings-dominant.** Author panic-path strings plus a boundary-free code signal. The realistic workhorse.
- **Tier 0, refuse.** Packed, headerless, or attribution-defeated inputs produce no rule and a stated reason. A generator that declines to emit an unsafe rule is worth more than one that always emits something.

### Independence, and a correction the design needed

Tier 1 multiplies two factors' improbabilities, which is only valid if the factors are independent. The panic-path strings are not independent of the code — they are how unhusk found the code in the first place. A rule that ANDs "this author function" with "the panic string that function references" counts one piece of evidence twice. So Tier 1's second factor has to come from genuinely separate evidence: a behavioral string (a hostname, a mutex name, a format string) the author chose for behavior, not for panic reporting.

The same non-independence has a consequence the design missed at first and measurement corrected. The original tier model included a "code-only" fallback for when strings are weak. That tier is incoherent: the code factor is downstream of the string attribution, so when the attribution strings die there is no code factor left to fall back to. A binary built with `--remap-path-prefix` has no author panic paths, therefore no attributed functions, therefore nothing to sign — code or otherwise. That case is Tier 0, not a code-only tier. The mislabeling sat in the architecture from the design stage and was only caught when a real `--remap-path-prefix` sample produced zero attributed functions.

## Results against real malware

Six in-the-wild Rust malware samples were selected as signable. Three were not usable, each for a distinct reason: `blackcat_x` (Windows PE, out of scope), `01flip_x` (`--remap-path-prefix` removed the panic paths — Tier 0), and `p2pinfect_x` (no ELF section headers, a raw/partial dump). The three usable samples — `krusty_x` (KrustyLoader, Tier 2), `akira_v2_x` (Akira, Tier 1), `blackcat_sphynx_x` (BlackCat Sphynx, Tier 2) — each produced a rule, self-fired on its own sample, and produced **zero false positives across 76 held-out benign binaries** (rule-of-three 95% upper bound ~3.9%). Full tables, the held-out methodology, and the Tier 1 independence measurement are in [`docs/validation.md`](docs/validation.md).

Only one of the three (Akira) earns Tier 1: it has 3 masked-code atoms and 22 rare behavioral strings (`/tmp/stop_vms.sh`, `/akiranew.txt`, a hardcoded token, ESXi paths) drawn from disjoint functions. BlackCat Sphynx has a single STRONG function, so its code atom and its one behavioral string come from that same function — no disjoint pairing exists, and one function cannot corroborate itself, so it declines to Tier 2. KrustyLoader harvests only generic std panic candidates common in the corpus, so none survive rarity filtering, and it also declines to Tier 2. This is the design's own prediction: malware author code is small, unhusk's recall is partial, and a clean independent behavioral string in `.rodata` is often absent — malware frequently encrypts or runtime-decrypts exactly those strings. Tier 2 is the realistic workhorse; Tier 1 is the fortunate case.

Half the signable set was unusable, and the three failures are not noise — they are the boundary, characterized. Wrong format (PE), attribution defeated (`--remap-path-prefix`), and no section headers (raw dump) are three distinct mechanisms that each map exactly where the tool stops and why. Deployed recall is bounded by unhusk's fragility, not by winnow's logic: winnow can only sign what unhusk can attribute.

## What is claimed, and what is not

- **Claimed:** across the three usable samples, zero false positives on a 76-binary held-out benign split (rule-of-three 95% upper bound ~3.9%), with the false-positive rate measured once rather than per family. One sample (Akira) earns the two-factor Tier 1 rule; the other two hold at Tier 2.
- **Not claimed:** a wild false-positive rate. Three rules against a 154-binary curated corpus is a start, not a representative study. n is small and the corpus is curated toward common crates.
- **Not claimed:** family or version coverage. Each rule fingerprints one binary by design.

## Reproducing the measurement

The numbers above are not meant to be taken on faith.

```sh
scripts/build_corpus.sh          # git-clone + cargo build the benign corpus into corpus/bin/
                                  # (manifest committed at corpus/manifest.csv)
scripts/measure_holdout.sh       # split the corpus into filter half A and held-out half B,
                                  # build rules against A, count false positives only on B
scripts/measure_independence.sh  # decompose each earned Tier 1 rule into code-only and
                                  # string-only variants, scan each against B
```

Both scripts write their raw output under `results/` (gitignored); [`docs/validation.md`](docs/validation.md) is the committed, curated snapshot of that output. `corpus/manifest.csv` lists every benign binary's source repo, commit, and build flags — the corpus itself isn't committed, only the recipe to rebuild it.

## Limitations

- The result rests on n=3 usable samples. The three unusable ones show how easily the input side breaks.
- Tier 1 is earned by one of the three (Akira) and declined by the other two. The multi-factor rule now fires on real malware, but on a thin base — a single earning sample. The independent behavioral string it needs is often absent or encrypted, so most samples reach Tier 2, not Tier 1.
- winnow inherits every one of unhusk's limits: x86-64 ELF only; defeated by packing, `--remap-path-prefix`, and `panic_immediate_abort`; partial recall; lower precision on async-heavy code, which malware skews toward.
- The benign corpus is 154 binaries curated toward common crates, not sampled from a representative population of Rust software. The false-positive number is only as good as the corpus is representative.

## Relationship to unhusk

unhusk is the backend; winnow is the rule generator behind its JSON contract. winnow consumes `unhusk --precision --json` for function boundaries, tiers, and panic-path attribution, and re-opens the ELF itself for raw bytes and non-panic strings. That re-parsing is the seam: the current contract carries neither raw bytes nor non-panic author strings, so the consumer re-derives what the producer already saw. The clean fix is a v2 contract that has unhusk emit per-function bytes and behavioral strings directly — a refactor, not a redesign, and not required for the tool to work.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
