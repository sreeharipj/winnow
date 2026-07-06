mod code;
mod elfview;
mod emit;
mod ingest;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};

/// Winnow — automated YARA-X signature generator for stripped Rust malware.
/// Phase 1: thinnest Tier-2 (strings-dominant) rule generator.
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
    let inputs = emit::RuleInputs {
        sample_name: &sample_name,
        sample_path: &args.elf,
        sample_sha256,
        min_anchors: census.min_anchors,
        strong_fn_count: strong.len(),
        anchor_strings: anchor_strings.into_iter().collect(),
        code_atoms,
    };
    let rule_text = emit::build_rule(&inputs);

    let out_path = args
        .output
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
    Ok(())
}

fn sha256_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}
