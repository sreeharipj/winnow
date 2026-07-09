/// Rule Assembler + Provenance Stamper (architecture §7.E, §7.F) — Tier 2.
///
/// Emits one YARA-X rule per sample: author panic-path strings (from
/// unhusk's `anchor_files`, already attributed — no independent rarity
/// filter yet, that needs the benign corpus and is Phase 3) plus the
/// boundary-free code atoms from `code.rs`. Portable byte-pattern core only;
/// no YARA-X-only condition is load-bearing (architecture §7.E), so these
/// rules also run under legacy YARA.
use std::path::Path;

use crate::code::CodeAtom;
use crate::mask::{MaskByte, MaskedAtom};

pub struct RuleInputs<'a> {
    pub sample_name: &'a str,
    pub sample_path: &'a Path,
    pub sample_sha256: String,
    pub min_anchors: usize,
    pub strong_fn_count: usize,
    pub anchor_strings: Vec<String>,
    pub code_atoms: Vec<CodeAtom>,
}

pub fn build_rule(inp: &RuleInputs) -> String {
    let rule_name = sanitize_ident(&format!("winnow_{}", inp.sample_name));
    let mut out = String::new();

    out.push_str(&format!("rule {} {{\n", rule_name));
    out.push_str("  meta:\n");
    out.push_str("    generator = \"winnow-phase1\"\n");
    out.push_str("    tier = \"2\"\n");
    out.push_str(&format!("    sample = \"{}\"\n", escape_str(inp.sample_name)));
    out.push_str(&format!(
        "    sample_path = \"{}\"\n",
        escape_str(&inp.sample_path.display().to_string())
    ));
    out.push_str(&format!("    sample_sha256 = \"{}\"\n", inp.sample_sha256));
    out.push_str(&format!("    min_anchors = {}\n", inp.min_anchors));
    out.push_str(&format!("    strong_functions = {}\n", inp.strong_fn_count));
    out.push_str(
        "    rests_on = \"author panic-path strings (unhusk anchor_files, confirming-tier \
         attribution) AND boundary-free call-site code atoms (unmasked, exact-byte, \
         self-consistent for on-disk file scanning). No independence resolver, no rarity \
         filter, no per-function masked hex — those are Phase 3, gated on the benign-corpus \
         FP measurement (Phase 2). This is a Tier 2 (strings-dominant) rule, not the Tier 1 \
         flagship.\"\n",
    );
    out.push_str("  strings:\n");
    for (i, s) in inp.anchor_strings.iter().enumerate() {
        out.push_str(&format!("    $panic{} = \"{}\" ascii\n", i, escape_str(s)));
    }
    for (i, atom) in inp.code_atoms.iter().enumerate() {
        out.push_str(&format!(
            "    $code{} = {{ {} }} // fn 0x{:x}\n",
            i,
            hex_bytes(&atom.bytes),
            atom.fn_start
        ));
    }
    out.push_str("  condition:\n");
    out.push_str("    uint32(0) == 0x464c457f and any of ($panic*) and any of ($code*)\n");
    out.push_str("}\n");
    out
}

/// Tier 1 flagship rule (architecture §5, §6, §7). Condition requires the
/// masked-code factor AND the independent behavioral-data factor — the two
/// things whose improbabilities are allowed to multiply (§6). Panic strings
/// are included only as confirming/informational context in `meta`, never
/// in the condition, so they are never double-counted as independent
/// evidence for the same functions that produced them.
pub struct Tier1Inputs<'a> {
    pub sample_name: &'a str,
    pub sample_path: &'a Path,
    pub sample_sha256: String,
    pub min_anchors: usize,
    pub strong_fn_count: usize,
    pub panic_strings: Vec<String>,
    pub masked_atoms: Vec<MaskedAtom>,
    pub behavior_strings: Vec<String>,
    pub corpus_size: usize,
}

pub fn build_tier1_rule(inp: &Tier1Inputs) -> String {
    let rule_name = sanitize_ident(&format!("winnow_tier1_{}", inp.sample_name));
    let mut out = String::new();

    out.push_str(&format!("rule {} {{\n", rule_name));
    out.push_str("  meta:\n");
    out.push_str("    generator = \"winnow-phase3\"\n");
    out.push_str("    tier = \"1\"\n");
    out.push_str(&format!("    sample = \"{}\"\n", escape_str(inp.sample_name)));
    out.push_str(&format!(
        "    sample_path = \"{}\"\n",
        escape_str(&inp.sample_path.display().to_string())
    ));
    out.push_str(&format!("    sample_sha256 = \"{}\"\n", inp.sample_sha256));
    out.push_str(&format!("    min_anchors = {}\n", inp.min_anchors));
    out.push_str(&format!("    strong_functions = {}\n", inp.strong_fn_count));
    out.push_str(&format!(
        "    confirming_panic_strings = \"{}\"\n",
        escape_str(&inp.panic_strings.join("; "))
    ));
    out.push_str(&format!(
        "    benign_corpus_size = {}\n",
        inp.corpus_size
    ));
    out.push_str(
        "    rests_on = \"masked-hex code factor (relocation-patched operands, \
         RIP-relative displacements, and 64-bit absolute immediates masked; whole-atom \
         substring-reduced against the benign corpus, architecture critique finding 2) AND \
         an independent non-panic author-data string (rarity-filtered against the same \
         corpus). Panic-path strings are confirming only (architecture section 6) and are \
         listed above in meta, not required by this rule's condition, so they are never \
         double-counted as independent evidence.\"\n",
    );
    out.push_str("  strings:\n");
    for (i, atom) in inp.masked_atoms.iter().enumerate() {
        out.push_str(&format!(
            "    $mcode{} = {{ {} }} // fn 0x{:x}\n",
            i,
            hex_masked(&atom.bytes),
            atom.fn_start
        ));
    }
    for (i, s) in inp.behavior_strings.iter().enumerate() {
        out.push_str(&format!(
            "    $behavior{} = \"{}\" ascii\n",
            i,
            escape_str(s)
        ));
    }
    out.push_str("  condition:\n");
    out.push_str("    uint32(0) == 0x464c457f and any of ($mcode*) and any of ($behavior*)\n");
    out.push_str("}\n");
    out
}

fn hex_masked(bytes: &[MaskByte]) -> String {
    bytes
        .iter()
        .map(|b| match b {
            MaskByte::Exact(v) => format!("{:02X}", v),
            MaskByte::Wildcard => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_ident(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
        if i == 0 && out.chars().next().unwrap().is_ascii_digit() {
            out.insert(0, '_');
        }
    }
    if out.is_empty() {
        out.push_str("winnow_rule");
    }
    out
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sanitize_ident_replaces_non_identifier_chars() {
        assert_eq!(sanitize_ident("a-b.c"), "a_b_c");
    }

    #[test]
    fn sanitize_ident_prefixes_a_leading_digit() {
        assert_eq!(sanitize_ident("123abc"), "_123abc");
    }

    #[test]
    fn sanitize_ident_falls_back_when_empty() {
        assert_eq!(sanitize_ident(""), "winnow_rule");
    }

    #[test]
    fn escape_str_escapes_quotes() {
        assert_eq!(escape_str(r#"he said "hi""#), r#"he said \"hi\""#);
    }

    #[test]
    fn escape_str_escapes_backslashes_before_quotes() {
        assert_eq!(escape_str(r"C:\path"), r"C:\\path");
    }

    #[test]
    fn hex_bytes_formats_uppercase_pairs() {
        assert_eq!(hex_bytes(&[0x00, 0xFF, 0x1A]), "00 FF 1A");
    }

    #[test]
    fn hex_masked_renders_wildcards() {
        let bytes = vec![
            MaskByte::Exact(0x01),
            MaskByte::Wildcard,
            MaskByte::Exact(0xFF),
        ];
        assert_eq!(hex_masked(&bytes), "01 ?? FF");
    }

    #[test]
    fn build_rule_includes_strings_and_condition() {
        let path = PathBuf::from("/tmp/sample.elf");
        let inputs = RuleInputs {
            sample_name: "sample",
            sample_path: &path,
            sample_sha256: "deadbeef".to_string(),
            min_anchors: 2,
            strong_fn_count: 1,
            anchor_strings: vec!["panic at \"src/main.rs\"".to_string()],
            code_atoms: vec![CodeAtom {
                fn_start: 0x1000,
                bytes: vec![0x90; 8],
            }],
        };

        let text = build_rule(&inputs);
        assert!(text.starts_with("rule winnow_sample {"));
        assert!(text.contains("$panic0 = \"panic at \\\"src/main.rs\\\"\" ascii"));
        assert!(text.contains("$code0 = { 90 90 90 90 90 90 90 90 }"));
        assert!(text.contains("any of ($panic*) and any of ($code*)"));
    }

    #[test]
    fn build_tier1_rule_condition_never_references_panic_strings() {
        let path = PathBuf::from("/tmp/sample.elf");
        let inputs = Tier1Inputs {
            sample_name: "sample",
            sample_path: &path,
            sample_sha256: "deadbeef".to_string(),
            min_anchors: 2,
            strong_fn_count: 1,
            panic_strings: vec!["src/main.rs".to_string()],
            masked_atoms: vec![MaskedAtom {
                fn_start: 0x1000,
                bytes: vec![MaskByte::Exact(0x90)],
            }],
            behavior_strings: vec!["hello world".to_string()],
            corpus_size: 75,
        };

        let text = build_tier1_rule(&inputs);
        let condition = text
            .lines()
            .find(|l| l.trim_start().starts_with("uint32(0)"))
            .expect("condition line present");
        assert!(condition.contains("$mcode*"));
        assert!(condition.contains("$behavior*"));
        assert!(!condition.contains("$panic"));
    }
}
