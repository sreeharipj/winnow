mod behavior;
mod code;
mod elfview;
mod emit;
mod ingest;
mod mask;
mod rarity;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};

/// Winnow — automated YARA-X signature generator for stripped Rust malware.
/// Phase 1: thinnest Tier-2 (strings-dominant) rule generator.
/// Phase 3 (--tier1): masked-hex + independent behavioral-data flagship,
/// gated on the benign corpus this project measures itself against.
#[derive(Parser)]
#[command(name = "winnow", version, about)]
struct Args {
    /// Path to the stripped ELF sample to generate a rule for.
    elf: PathBuf,

    /// Output .yar path. Defaults to "<sample-name>.yar" in the CWD.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Explicit path to the unhusk binary (overrides PATH / sibling lookup).
    #[arg(long)]
    unhusk_bin: Option<PathBuf>,

    /// Also attempt the Tier 1 flagship rule (architecture §5, Phase 3):
    /// masked-hex code substring-reduced against the benign corpus, AND an
    /// independent non-panic author string rarity-filtered against it.
    /// Requires --corpus-dir. Only earned (and only written) if both
    /// factors survive; otherwise winnow explains why and keeps Tier 2.
    #[arg(long)]
    tier1: bool,

    /// Directory of benign corpus binaries (see corpus/manifest.csv).
    /// Required with --tier1.
    #[arg(long)]
    corpus_dir: Option<PathBuf>,

    /// Output path for the Tier 1 rule. Defaults to "<sample-name>_tier1.yar".
    #[arg(long)]
    tier1_output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let census = ingest::run_unhusk(&args.elf, args.unhusk_bin.as_deref())
        .context("running unhusk")?;

    let strong: Vec<&ingest::FnRange> = census
        .functions
        .iter()
        .filter(|f| f.tier == "strong")
        .collect();

    // Tier 0 — refuse. No STRONG-tier author functions at all: unhusk saw a
    // packed binary, aggressive `--remap-path-prefix`, or genuinely no
    // reachable user panic evidence. A tool that declines beats one that
    // always emits something (architecture §5, non-negotiable #5).
    if strong.is_empty() {
        eprintln!(
            "winnow: TIER 0 REFUSE — no STRONG-tier author functions in {}",
            args.elf.display()
        );
        eprintln!("        (packed binary, aggressive path remapping, or no reachable user panic evidence)");
        std::process::exit(1);
    }

    let elf = elfview::ParsedElf::load(&args.elf)?;
    let Some(text) = elf.section(".text") else {
        eprintln!(
            "winnow: TIER 0 REFUSE — no .text section in {} (packed?)",
            args.elf.display()
        );
        std::process::exit(1);
    };

    let mut anchor_strings: BTreeSet<String> = BTreeSet::new();
    let mut code_atoms = Vec::new();
    for f in &strong {
        for a in &f.anchor_files {
            anchor_strings.insert(a.clone());
        }
        code_atoms.extend(code::extract_code_atoms(text, f.start, f.end));
    }

    // Tier 2 needs the string factor. Phase 1 does not implement the Tier 3
    // (code-only) fallback — refuse rather than emit a code-only rule that
    // hasn't earned its FP argument. This is the `01flip_x` / remap-path
    // case (architecture §5, Tier 3) surfacing here as an honest refusal.
    if anchor_strings.is_empty() {
        eprintln!(
            "winnow: STRONG functions carry no anchor_files in {} — strings-weak (likely \
             --remap-path-prefix). This is the Tier 3 (code-only) case; Phase 1 only \
             implements Tier 2, so winnow refuses rather than emit an unearned rule.",
            args.elf.display()
        );
        std::process::exit(2);
    }

    let sample_sha256 = sha256_file(&args.elf)?;
    let sample_name = args
        .elf
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sample")
        .to_string();

    let anchor_string_count = anchor_strings.len();
    let code_atom_count = code_atoms.len();
    let panic_strings: Vec<String> = anchor_strings.into_iter().collect();
    let inputs = emit::RuleInputs {
        sample_name: &sample_name,
        sample_path: &args.elf,
        sample_sha256: sample_sha256.clone(),
        min_anchors: census.min_anchors,
        strong_fn_count: strong.len(),
        anchor_strings: panic_strings.clone(),
        code_atoms,
    };
    let rule_text = emit::build_rule(&inputs);

    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.yar", sample_name)));
    std::fs::write(&out_path, &rule_text)
        .with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "winnow: wrote {} ({} STRONG fns, {} panic strings, {} code atoms)",
        out_path.display(),
        inputs.strong_fn_count,
        anchor_string_count,
        code_atom_count
    );

    if args.tier1 {
        run_tier1(&args, &census, &strong, &elf, text, &sample_name, &sample_sha256, &panic_strings)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tier1(
    args: &Args,
    census: &ingest::Census,
    strong: &[&ingest::FnRange],
    elf: &elfview::ParsedElf,
    text: &elfview::Section,
    sample_name: &str,
    sample_sha256: &str,
    panic_strings: &[String],
) -> Result<()> {
    let Some(corpus_dir) = &args.corpus_dir else {
        eprintln!("winnow: --tier1 requires --corpus-dir (the benign corpus to measure against)");
        std::process::exit(3);
    };
    let corpus = rarity::Corpus::load(corpus_dir)
        .with_context(|| format!("loading corpus from {}", corpus_dir.display()))?;
    println!(
        "winnow: tier1 — measuring against benign corpus ({} files)",
        corpus.len()
    );

    let rodata = elf.section(".rodata");

    // Masked-hex code factor, substring-reduced against the corpus.
    let mut masked_atoms = Vec::new();
    for f in strong {
        let Some(atom) = mask::mask_function(text, &elf.rela_relative, f.start, f.end) else {
            continue;
        };
        let collisions = corpus.masked_atom_collisions(&atom);
        if collisions.is_empty() {
            println!(
                "winnow: tier1 — masked atom for fn 0x{:x} discriminative ({} of {} bytes wildcarded)",
                f.start,
                atom.wildcard_count(),
                atom.bytes.len()
            );
            masked_atoms.push(atom);
        } else {
            eprintln!(
                "winnow: tier1 — masked atom for fn 0x{:x} collides with {} benign file(s) \
                 ({}), dropping it (critique finding 2: unreduced masked hex is unearned)",
                f.start,
                collisions.len(),
                collisions.join(", ")
            );
        }
    }

    // Independent non-panic author-data factor, rarity-filtered against the
    // corpus. Excludes anything already present in the panic-path set so the
    // two factors stay genuinely separate (architecture §6).
    let mut behavior_candidates: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    if let Some(rodata) = rodata {
        for f in strong {
            for b in behavior::extract_behavior_strings(text, rodata, f.start, f.end) {
                if !panic_strings.iter().any(|p| p == &b.text) {
                    behavior_candidates.entry(b.text).or_insert(b.fn_start);
                }
            }
        }
    }
    let mut behavior_strings = Vec::new();
    for (s, fn_start) in behavior_candidates {
        if corpus.string_is_rare(&s) {
            println!("winnow: tier1 — behavioral string {:?} (fn 0x{:x}) is rare — kept", s, fn_start);
            behavior_strings.push(s);
        } else {
            eprintln!(
                "winnow: tier1 — candidate behavioral string {:?} appears in the benign \
                 corpus, dropping it (not rare)",
                s
            );
        }
    }

    if masked_atoms.is_empty() || behavior_strings.is_empty() {
        eprintln!(
            "winnow: TIER 1 NOT EARNED for {} — {}. Tier 1 is the fortunate case \
             (architecture §5); Tier 2 rule above still stands.",
            sample_name,
            match (masked_atoms.is_empty(), behavior_strings.is_empty()) {
                (true, true) => "no masked-code atom survived substring reduction AND no \
                    independent behavioral string survived rarity filtering",
                (true, false) => "no masked-code atom survived substring reduction",
                (false, true) => "no independent (non-panic) behavioral string survived \
                    rarity filtering against the corpus",
                (false, false) => unreachable!(),
            }
        );
        return Ok(());
    }

    let inputs = emit::Tier1Inputs {
        sample_name,
        sample_path: &args.elf,
        sample_sha256: sample_sha256.to_string(),
        min_anchors: census.min_anchors,
        strong_fn_count: strong.len(),
        panic_strings: panic_strings.to_vec(),
        masked_atoms,
        behavior_strings,
        corpus_size: corpus.len(),
    };
    let rule_text = emit::build_tier1_rule(&inputs);

    let out_path = args
        .tier1_output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}_tier1.yar", sample_name)));
    std::fs::write(&out_path, &rule_text)
        .with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "winnow: wrote {} (TIER 1 EARNED — {} masked-code atoms, {} independent behavioral strings)",
        out_path.display(),
        inputs.masked_atoms.len(),
        inputs.behavior_strings.len()
    );
    Ok(())
}

fn sha256_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}
