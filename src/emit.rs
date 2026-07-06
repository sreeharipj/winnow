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
