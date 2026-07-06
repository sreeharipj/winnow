/// Per-function masked hex (architecture §4, §7.B) — the Tier 1 flagship
/// code factor, built only in Phase 3.
///
/// "Masking is correctness, not resilience" (architecture §4): we mask only
/// bytes that are *provably volatile*, keeping everything else byte-exact.
/// Three sources of volatility, all evidence-based rather than assumed:
///
///   1. A memory operand's RIP-relative displacement — named explicitly in
///      the architecture doc. Its on-disk bytes are in fact a link-time
///      constant (RIP-relative addressing is already position-independent),
///      but we mask it anyway per the doc's stated policy, since Winnow's
///      output is meant to be safe under stricter (e.g. memory-scan) reuse
///      than the file-scan self-test this project measures.
///   2. A 64-bit immediate (`movabs`-style absolute address) — the classic
///      vector for embedding a pointer that ASLR/relocation can move.
///   3. Any byte range that a real `.rela.dyn` `R_X86_64_RELATIVE` entry
///      actually patches at load time — checked against `ParsedElf::
///      rela_relative` rather than guessed from instruction shape.
///
/// Ordinary displacements (`[rbp-8]`, stack/heap-relative) and small
/// immediates are left exact — masking them would only throw away
/// specificity for no correctness reason.
use iced_x86::{Decoder, DecoderOptions, Instruction, Register};

use crate::elfview::{RelaRelative, Section};

/// One byte of a masked-hex atom: an exact value, or a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskByte {
    Exact(u8),
    Wildcard,
}

#[derive(Debug, Clone)]
pub struct MaskedAtom {
    pub fn_start: u64,
    pub bytes: Vec<MaskByte>,
}

impl MaskedAtom {
    pub fn wildcard_count(&self) -> usize {
        self.bytes
            .iter()
            .filter(|b| matches!(b, MaskByte::Wildcard))
            .count()
    }
}

/// Build one masked-hex atom covering the whole `[fn_start, fn_end)` range.
pub fn mask_function(
    text: &Section,
    rela: &[RelaRelative],
    fn_start: u64,
    fn_end: u64,
) -> Option<MaskedAtom> {
    let len = (fn_end - fn_start) as usize;
    let fn_bytes = text.slice_at(fn_start, len)?;

    let mut out: Vec<MaskByte> = fn_bytes.iter().map(|&b| MaskByte::Exact(b)).collect();

    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_start, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let instr_start = (instr.ip() - fn_start) as usize;
        let instr_len = instr.len();
        if instr_start + instr_len > out.len() {
            break;
        }

        let co = decoder.get_constant_offsets(&instr);

        // 1. RIP-relative displacement.
        if co.has_displacement() && instr.memory_base() == Register::RIP {
            mask_range(&mut out, instr_start, co.displacement_offset(), co.displacement_size());
        }

        // 2. 64-bit absolute immediate (movabs and friends).
        if co.has_immediate() && co.immediate_size() == 8 {
            mask_range(&mut out, instr_start, co.immediate_offset(), co.immediate_size());
        }
        if co.has_immediate2() && co.immediate_size2() == 8 {
            mask_range(&mut out, instr_start, co.immediate_offset2(), co.immediate_size2());
        }

        // 3. Defensive: any byte a real relocation patches at load time.
        for r in rela {
            if r.offset >= instr.ip() && r.offset < instr.ip() + instr_len as u64 {
                let off = (r.offset - instr.ip()) as usize;
                mask_range(&mut out, instr_start, off, 8.min(instr_len - off));
            }
        }
    }

    Some(MaskedAtom {
        fn_start,
        bytes: out,
    })
}

fn mask_range(out: &mut [MaskByte], instr_start: usize, rel_off: usize, size: usize) {
    let len = out.len();
    let start = (instr_start + rel_off).min(len);
    let end = (start + size).min(len);
    for b in &mut out[start..end] {
        *b = MaskByte::Wildcard;
    }
}
