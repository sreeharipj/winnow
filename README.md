# winnow

Generates YARA-X rules for stripped x86-64 Rust malware. One binary in, one rule for that binary out. Built on [unhusk](https://github.com/sreeharipj/unhusk), which isolates the author-written functions in a stripped Rust binary from panic metadata.

> Experimental research project, single author. Validated on 3 usable in-the-wild Rust malware samples and a 75-binary benign Rust corpus, static analysis only, samples never executed. x86-64 ELF only. Numbers and interfaces change as evidence accumulates.

unhusk answers "which bytes in this stripped Rust binary are the author's." winnow turns that answer into a signature. Because unhusk's inputs are attributed to the author by construction — panic-metadata provenance, not a heuristic — the bytes and strings winnow builds a rule from are the author's own, not stdlib and not dependency crates. A rule built only from author-unique material should not fire on unrelated software. winnow exists to find out whether that holds, and it is built so the claim has to survive a measurement instead of an argument.

## One binary, one rule (the design, not a shortcut)

winnow does not generalize across a malware family or across versions. One sample produces one rule that fingerprints that sample. If the rule also catches a later build because the author never touched the fingerprinted functions, that is a free hit — never a target, never something a rule is loosened to achieve.

This is the whole false-positive strategy. Generalization is where false positives come from: every step a signature takes toward matching a family is a step toward matching something benign. winnow starts from material guaranteed unique to one author and its only job is to keep that uniqueness intact all the way to the rule. Chasing the next version would trade a real present guarantee for a speculative future hit, so it doesn't.

## Measurement gates construction

The governing rule of the project: no component ships before the experiment that would falsify its reason to exist has run.

The design claim — near-zero false positives from author-unique inputs — is an argument, and the argument has a hole. "This string is rare," "this pattern won't collide," "these bytes are discriminative" are all claims about a background distribution of benign code. You cannot know a string is rare without a model of what is common, and that model is a benign corpus. So the honest claim is not "no benign corpus needed." It is **no per-family validation**: the benign false-positive rate is measured once, and per-rule specificity thereafter rests on author-attribution, not on re-validating each family against negative data. Every phase is ordered to produce that measurement early and let it decide what gets built next.

## The benign corpus

75 benign x86-64 ELF Rust binaries, release-built and stripped, spanning CLI, systems, async, and parallel tools — the shapes the malware set also takes. A subset had `.eh_frame` removed to mirror the boundary-degraded regime.

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

The three usable samples each produced a rule:

| Sample | Family | Self-fires | Benign FPs (of 75) |
|---|---|:---:|---:|
| `krusty_x` | KrustyLoader | yes | 0 |
| `akira_v2_x` | Akira | yes | 0 |
| `blackcat_sphynx_x` | BlackCat Sphynx | yes | 0 |

Zero false positives across three rules and 75 benign binaries. The scan was sanity-checked against a trivially-true rule first, which matched all 75 — confirming the zero is a real result and not a broken scanner reporting no matches for the wrong reason.

## Tier 1 was built and not earned

The Tier 1 apparatus was built in full and gated on the corpus:

- **Masked-hex.** Masks relocation-patched displacements, 64-bit absolute immediates, and the bytes an actual `.rela.dyn` relocation patches, located via iced-x86 constant offsets — not blanket masking. Every masked atom across the corpus was discriminative, zero collisions, and every one still self-fired: the masking is specific without breaking correctness.
- **Behavioral-string extraction.** The first version had a real bug. It paired any LEA in an 8-instruction lookback window and sliced the underlying bytes, gluing unrelated strings into plausible-looking garbage. (unhusk uses a similar lookback safely, but only because it has type-shape and boundary checks that general printable-string extraction does not.) Caught by disassembling a flagged function by hand and finding the extraction did not match the instructions. Fixed by requiring strict zero-gap `lea;mov` adjacency.

With the corrected, honest heuristic, none of the three samples produced a qualifying Tier 1 rule. This is not a failure. It confirms the design's own prediction: malware author code is small, unhusk's recall is partial, STRONG is a subset of that, and a clean independent behavioral string in `.rodata` is usually absent — malware frequently encrypts or runtime-decrypts exactly those strings. Tier 2 is the realistic workhorse; Tier 1 is the fortunate case. The apparatus to manufacture a Tier 1 hit existed and was correct, and the measurement said none was earned.

## The operational envelope

Half the signable set was unusable, and the three failures are not noise — they are the boundary, characterized. Wrong format (PE), attribution defeated (`--remap-path-prefix`), and no section headers (raw dump) are three distinct mechanisms that each map exactly where the tool stops and why. Deployed recall is bounded by unhusk's fragility, not by winnow's logic: winnow can only sign what unhusk can attribute.

## What is claimed, and what is not

- **Claimed:** across the three usable samples, zero false positives against a 75-binary benign Rust corpus, with the false-positive rate measured once rather than per family.
- **Not claimed:** a wild false-positive rate. Three rules and 75 benign binaries is a start, not a representative study. n is small and the corpus is curated.
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
scripts/measure.sh               # generates Tier 2 rules for the malware samples and
                                  # scans them against the full corpus -> results/fp_table.md
```

`results/tier1_report.md` records the Tier 1 attempt (per-atom corpus-collision checks and
the reason Tier 1 wasn't earned for each sample). `corpus/manifest.csv` lists every benign
binary's source repo, commit, and build flags — the corpus itself isn't committed, only the
recipe to rebuild it.

## Limitations

- The result rests on n=3 usable samples. The three unusable ones show how easily the input side breaks.
- Tier 1 is unearned on the current set. The multi-factor rule is designed and validated as machinery but has not fired on real malware, because the independent behavioral string it needs is usually absent or encrypted.
- winnow inherits every one of unhusk's limits: x86-64 ELF only; defeated by packing, `--remap-path-prefix`, and `panic_immediate_abort`; partial recall; lower precision on async-heavy code, which malware skews toward.
- The benign corpus is curated toward common crates, not sampled from a representative population of Rust software. The false-positive number is only as good as the corpus is representative.

## Relationship to unhusk

unhusk is the backend; winnow is the rule generator behind its JSON contract. winnow consumes `unhusk --precision --json` for function boundaries, tiers, and panic-path attribution, and re-opens the ELF itself for raw bytes and non-panic strings. That re-parsing is the seam: the current contract carries neither raw bytes nor non-panic author strings, so the consumer re-derives what the producer already saw. The clean fix is a v2 contract that has unhusk emit per-function bytes and behavioral strings directly — a refactor, not a redesign, and not required for the tool to work.

## License

Dual-licensed: AGPL-3.0 for open-source and general use, or a commercial license for proprietary use. See `LICENSE`.
