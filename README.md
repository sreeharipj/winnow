# winnow

Generates YARA-X rules for stripped x86-64 Rust malware. One binary in, one rule for that binary out. Built on [unhusk](https://github.com/sreeharipj/unhusk), which isolates the author-written functions in a stripped Rust binary from panic metadata.

unhusk answers "which bytes in this stripped Rust binary are the author's." winnow turns that answer into a signature. Because unhusk's inputs are attributed to the author by construction — panic-metadata provenance, not a heuristic — the bytes and strings winnow builds a rule from are the author's own, not stdlib and not dependency crates. A rule built only from author-unique material should not fire on unrelated software. winnow exists to find out whether that holds, and it is built so the claim has to survive a measurement instead of an argument.

## One binary, one rule (the design, not a shortcut)

winnow does not generalize across a malware family or across versions. One sample produces one rule that fingerprints that sample. If the rule also catches a later build because the author never touched the fingerprinted functions, that is a free hit — never a target, never something a rule is loosened to achieve.

This is the whole false-positive strategy. Generalization is where false positives come from: every step a signature takes toward matching a family is a step toward matching something benign. winnow starts from material guaranteed unique to one author and its only job is to keep that uniqueness intact all the way to the rule. Chasing the next version would trade a real present guarantee for a speculative future hit, so it doesn't.

## Measurement gates construction

The governing rule of the project: no component ships before the experiment that would falsify its reason to exist has run.

The design claim — near-zero false positives from author-unique inputs — is an argument, and the argument has a hole. "This string is rare," "this pattern won't collide," "these bytes are discriminative" are all claims about a background distribution of benign code. You cannot know a string is rare without a model of what is common, and that model is a benign corpus. So the honest claim is not "no benign corpus needed." It is **no per-family validation**: the benign false-positive rate is measured once, and per-rule specificity thereafter rests on author-attribution, not on re-validating each family against negative data. Every phase is ordered to produce that measurement early and let it decide what gets built next.

## The benign corpus

154 benign x86-64 ELF Rust binaries, release-built and stripped, spanning CLI, systems, async, and parallel tools — the shapes the malware set also takes. A subset had `.eh_frame` removed to mirror the boundary-degraded regime. It began at 75 and was grown to 154; the only thing that growth buys is a tighter false-positive interval, so it costs nothing in the pipeline to keep growing it.

The corpus is split into a filter half (A) and a disjoint held-out half (B). Rules are built against A, and their false positives are counted only on B. A rule's strings are selected for being *absent* from the filter corpus, so counting false positives on that same corpus is circular — no corpus binary can match a rule whose strings were chosen for being absent from it. Measuring on a held-out B that the filters never saw makes a clean number a measurement instead of a restatement of the filtering step.

One trap, stated because it silently defeats the whole corpus: the binaries are built with `git clone` + `cargo build --release`, not `cargo install`. `cargo install` builds from `~/.cargo/registry/`, which rewrites the tool's own source paths to `registry/...`, and unhusk then classifies the author's own code as a dependency instead of User. A corpus built that way exercises the wrong code path — not the User-attribution path the malware rules rest on — and reports a meaningless number.

## Tiers

winnow emits the strongest rule its evidence supports and stamps each rule with what it rests on. The evidence is not uniformly available — inherited from unhusk, panic strings survive far more stripping than function boundaries do — so the generator degrades rather than failing shut.

- **Tier 1, multi-factor.** Masked-hex from STRONG author functions AND an independent behavioral string. The strongest rule; requires the coincidence of author-unique code and author-unique data that do not co-vary.
- **Tier 2, strings-dominant.** Author panic-path strings plus a boundary-free code signal. The realistic workhorse (see below).
- **Tier 0, refuse.** Packed, headerless, or attribution-defeated inputs produce no rule and a stated reason. A generator that declines to emit an unsafe rule is worth more than one that always emits something.

### Independence, and a correction the design needed

Tier 1 multiplies two factors' improbabilities, which is only valid if the factors are independent. The panic-path strings are not independent of the code — they are how unhusk found the code in the first place. A rule that ANDs "this author function" with "the panic string that function references" counts one piece of evidence twice. So Tier 1's second factor has to come from genuinely separate evidence: a behavioral string (a hostname, a mutex name, a format string) the author chose for behavior, not for panic reporting.

The same non-independence has a consequence the design missed at first and measurement corrected. The original tier model included a "code-only" fallback for when strings are weak. That tier is incoherent: the code factor is downstream of the string attribution, so when the attribution strings die there is no code factor left to fall back to. A binary built with `--remap-path-prefix` has no author panic paths, therefore no attributed functions, therefore nothing to sign — code or otherwise. That case is Tier 0, not a code-only tier. The mislabeling sat in the architecture from the design stage and was only caught when a real `--remap-path-prefix` sample produced zero attributed functions.

## What the measurement found

Six in-the-wild Rust malware samples were selected as signable. Three were not usable, for three distinct reasons:

| Sample | Family | Outcome |
|---|---|---|
| `blackcat_x` | BlackCat/ALPHV | Windows PE, not ELF. Out of scope. |
| `01flip_x` | 01flip | Zero attributed functions — `--remap-path-prefix` removed the panic paths, so unhusk has nothing to attribute. Tier 0. |
| `p2pinfect_x` | P2PInfect | No ELF section headers (raw/partial dump). unhusk finds no `.rela.dyn` to read. |

The three usable samples each produced a rule. Each self-fires on its own sample, and each was scanned against the 76-binary held-out split B:

| Sample | Family | Rule earned | Benign FPs on held-out B (76) |
|---|---|:---:|---:|
| `krusty_x` | KrustyLoader | Tier 2 | 0 |
| `akira_v2_x` | Akira | Tier 1 (two-factor) | 0 |
| `blackcat_sphynx_x` | BlackCat Sphynx | Tier 2 | 0 |

Zero false positives across three rules and 76 held-out benign binaries — a rule-of-three 95% upper bound of about 3.9% at this N (it was about 8% at B=36, before the corpus was grown). An early scan was sanity-checked against a trivially-true rule, which matched every corpus binary, confirming a zero is a real result and not a broken scanner reporting no matches for the wrong reason.

## Tier 1: earned once, declined twice

The Tier 1 apparatus pairs a masked-hex code factor with an independent behavioral string, and it is gated on the corpus:

- **Masked-hex.** Masks relocation-patched displacements, 64-bit absolute immediates, and the bytes an actual `.rela.dyn` relocation patches, located via iced-x86 constant offsets — not blanket masking. Each atom is then reduced from the whole function to its most discriminative 64-byte window and checked against the corpus: a 64-byte window can collide where a whole-function atom effectively cannot, so the reduction is a real specificity test rather than a free zero. Across the corpus every kept atom was discriminative with zero collisions and still self-fired.
- **Behavioral-string extraction.** The first version had a real bug: it paired any LEA in an 8-instruction lookback window and sliced the underlying bytes, gluing unrelated strings into plausible-looking garbage. (unhusk uses a similar lookback safely, but only because it has type-shape and boundary checks that general printable-string extraction does not.) It was caught by disassembling a flagged function by hand. The obvious fix — requiring the length to be the literal next instruction after the `lea` — turned out to recover *zero* strings on all three real samples, because rustc/LLVM routinely separates the length from the pointer load (argument setup in between, `push imm; pop`, or storing the length as one half of a fat pointer). The working version is a short register-dataflow window that stops the moment the pointer register is redefined, which is what actually prevents a stale `lea` from being spliced onto an unrelated later length.

On the current set, one sample earns Tier 1 and two decline:

- **Akira** earns it — 3 masked-code atoms and 22 rare behavioral strings (`/tmp/stop_vms.sh`, `/akiranew.txt`, a hardcoded token, ESXi paths), drawn from disjoint functions, with zero false positives on the 76 held-out binaries.
- **BlackCat Sphynx** has a single STRONG function. Its code atom and its one behavioral string (`esxcli … vm process list`) come from that same function, so no disjoint pairing exists; it declines to Tier 2. One function cannot corroborate itself.
- **KrustyLoader** harvests only generic std panic candidates, all common in the corpus, so none survive rarity filtering; it declines to Tier 2.

Two declining is the design's own prediction: malware author code is small, unhusk's recall is partial, STRONG is a subset of that, and a clean independent behavioral string in `.rodata` is often absent — malware frequently encrypts or runtime-decrypts exactly those strings. Tier 2 is the realistic workhorse; Tier 1 is the fortunate case. What changed from an earlier state of this project is that the behavioral-string extraction now recovers real author strings, so the fortunate case is no longer empty.

## The operational envelope

Half the signable set was unusable, and the three failures are not noise — they are the boundary, characterized. Wrong format (PE), attribution defeated (`--remap-path-prefix`), and no section headers (raw dump) are three distinct mechanisms that each map exactly where the tool stops and why. Deployed recall is bounded by unhusk's fragility, not by winnow's logic: winnow can only sign what unhusk can attribute.

## What is claimed, and what is not

- **Claimed:** across the three usable samples, zero false positives on a 76-binary held-out benign split (rule-of-three 95% upper bound ~3.9%), with the false-positive rate measured once rather than per family. One sample (Akira) earns the two-factor Tier 1 rule; the other two hold at Tier 2.
- **Not claimed:** a wild false-positive rate. Three rules against a 154-binary curated corpus is a start, not a representative study. n is small and the corpus is curated toward common crates.
- **Not claimed:** family or version coverage. Each rule fingerprints one binary by design.

## Usage

```sh
# unhusk must be on PATH (or --unhusk-bin <path>); winnow shells out to
# `unhusk --precision --json` and re-opens the ELF itself for bytes/strings.

# Tier 2 (workhorse): generate a YARA-X rule for a stripped Rust malware binary
winnow <stripped-elf>                     # emits <name>.yar

# Also attempt Tier 1 (masked-hex + independent behavioral string), gated on
# the benign corpus this project measured itself against:
winnow <stripped-elf> --tier1 --corpus-dir corpus/bin
                                           # emits <name>.yar and, only if
                                           # earned, <name>_tier1.yar
```

## Reproducing the measurement

The headline numbers above are not meant to be taken on faith.

```sh
scripts/build_corpus.sh          # git-clone + cargo build the benign corpus into corpus/bin/
                                  # (manifest committed at corpus/manifest.csv)
scripts/measure_holdout.sh       # split the corpus into filter half A and held-out half B,
                                  # build rules against A, count false positives only on B
                                  # -> results/fp_holdout.md and results/tier1_report.md
scripts/measure_independence.sh  # decompose each earned Tier 1 rule into code-only and
                                  # string-only variants, scan each against B
                                  # -> results/fp_independence.md
```

`results/tier1_report.md` records the Tier 1 attempt for each sample (per-atom corpus-collision
checks, which behavioral strings were kept or dropped, the disjoint-function partition, and the
reason Tier 1 was or wasn't earned). `corpus/manifest.csv` lists every benign binary's source
repo, commit, and build flags — the corpus itself isn't committed, only the recipe to rebuild it.

## Limitations

- The result rests on n=3 usable samples. The three unusable ones show how easily the input side breaks.
- Tier 1 is earned by one of the three (Akira) and declined by the other two. The multi-factor rule now fires on real malware, but on a thin base — a single earning sample. The independent behavioral string it needs is often absent or encrypted, so most samples reach Tier 2, not Tier 1.
- winnow inherits every one of unhusk's limits: x86-64 ELF only; defeated by packing, `--remap-path-prefix`, and `panic_immediate_abort`; partial recall; lower precision on async-heavy code, which malware skews toward.
- The benign corpus is 154 binaries curated toward common crates, not sampled from a representative population of Rust software. The false-positive number is only as good as the corpus is representative.

## Relationship to unhusk

unhusk is the backend; winnow is the rule generator behind its JSON contract. winnow consumes `unhusk --precision --json` for function boundaries, tiers, and panic-path attribution, and re-opens the ELF itself for raw bytes and non-panic strings. That re-parsing is the seam: the current contract carries neither raw bytes nor non-panic author strings, so the consumer re-derives what the producer already saw. The clean fix is a v2 contract that has unhusk emit per-function bytes and behavioral strings directly — a refactor, not a redesign, and not required for the tool to work.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
