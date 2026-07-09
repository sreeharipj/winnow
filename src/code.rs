/// Boundary-free code signal (architecture §5, Tier 2 / §7.B, restricted to
/// what Phase 1 needs).
///
/// Full per-function masked hex — mask every relocation-patched operand,
/// RIP-relative displacement, and absolute address across the *entire*
/// function body — is the Tier 1 flagship code factor (architecture §4, §7.B)
/// and is explicitly DEFERRED to Phase 3, where it ships together with
/// discriminative-substring reduction against the benign corpus (critique
/// finding 2: an unreduced masked-hex factor's specificity is unestablished).
///
/// Phase 1's code contribution is smaller in scope on purpose: short, exact
/// byte windows anchored on each direct CALL site inside a STRONG-tier
/// function. No masking is applied here. That is safe specifically because
/// Winnow measures itself by scanning the *same on-disk file* the rule was
/// built from (§8's claim is about a YARA-X static-file scan, not a live
/// process image) — a near CALL's rel32 encoding is a link-time constant
/// (IP-relative, so already position-independent) and is bit-for-bit
/// identical every time that file is read. It is not a load-bearing
/// specificity claim; it is a call-site-shaped exact-byte atom, which is what
/// "boundary-free" means here: no full-function mask pass, just local
/// windows around call sites.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use crate::elfview::Section;

const CTX_BEFORE: u64 = 6;
const MIN_ATOM_LEN: usize = 8;
const MAX_ATOMS_PER_FN: usize = 3;

#[derive(Debug, Clone)]
pub struct CodeAtom {
    pub fn_start: u64,
    pub bytes: Vec<u8>,
}

/// Extract up to `MAX_ATOMS_PER_FN` call-site byte windows from a STRONG
/// function's `[fn_start, fn_end)` range. Falls back to a fixed-size window
/// from the function's entry if it contains no direct near calls (leaf
/// functions, e.g. small crypto primitives).
pub fn extract_code_atoms(text: &Section, fn_start: u64, fn_end: u64) -> Vec<CodeAtom> {
    let Some(fn_bytes) = text.slice_at(fn_start, (fn_end - fn_start) as usize) else {
        return Vec::new();
    };

    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut atoms = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if atoms.len() >= MAX_ATOMS_PER_FN {
            break;
        }
        if instr.mnemonic() != Mnemonic::Call {
            continue;
        }
        // Only direct near calls — indirect calls (register/memory operand)
        // carry no useful byte-level identity for this signal.
        let is_near_direct = matches!(
            instr.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
        if !is_near_direct {
            continue;
        }

        let ctx_start = instr.ip().saturating_sub(CTX_BEFORE).max(fn_start);
        let snippet_end = instr.ip() + instr.len() as u64;
        let Some(snippet) = text.slice_at(ctx_start, (snippet_end - ctx_start) as usize) else {
            continue;
        };
        if snippet.len() >= MIN_ATOM_LEN {
            atoms.push(CodeAtom {
                fn_start,
                bytes: snippet.to_vec(),
            });
        }
    }

    if atoms.is_empty() {
        let win = (fn_end - fn_start).min(24) as usize;
        if let Some(snippet) = text.slice_at(fn_start, win) {
            if snippet.len() >= MIN_ATOM_LEN {
                atoms.push(CodeAtom {
                    fn_start,
                    bytes: snippet.to_vec(),
                });
            }
        }
    }

    atoms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elfview::Section;

    const FN_START: u64 = 0x1000;

    fn text_section(bytes: &[u8]) -> Section {
        Section {
            vaddr: FN_START,
            data: bytes.to_vec(),
        }
    }

    #[test]
    fn extracts_context_window_around_a_direct_call() {
        let mut bytes = vec![0x90; 6]; // padding before the call
        bytes.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call rel32
        let fn_end = FN_START + bytes.len() as u64;
        let text = text_section(&bytes);

        let atoms = extract_code_atoms(&text, FN_START, fn_end);
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].fn_start, FN_START);
        assert_eq!(atoms[0].bytes, bytes);
    }

    #[test]
    fn ignores_indirect_calls_and_falls_back_to_entry_window() {
        let mut bytes = vec![0x90; 10];
        bytes.extend_from_slice(&[0xFF, 0xD0]); // call rax (indirect)
        let fn_end = FN_START + bytes.len() as u64;
        let text = text_section(&bytes);

        let atoms = extract_code_atoms(&text, FN_START, fn_end);
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].bytes, bytes); // fallback: whole (short) function
    }

    #[test]
    fn caps_atoms_at_three_per_function() {
        let mut bytes = Vec::new();
        for _ in 0..4 {
            bytes.extend_from_slice(&[0x90; 6]);
            bytes.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        }
        let fn_end = FN_START + bytes.len() as u64;
        let text = text_section(&bytes);

        let atoms = extract_code_atoms(&text, FN_START, fn_end);
        assert_eq!(atoms.len(), MAX_ATOMS_PER_FN);
    }

    #[test]
    fn leaf_function_too_short_for_any_atom_yields_nothing() {
        let bytes = vec![0x90; 4]; // shorter than MIN_ATOM_LEN
        let fn_end = FN_START + bytes.len() as u64;
        let text = text_section(&bytes);

        let atoms = extract_code_atoms(&text, FN_START, fn_end);
        assert!(atoms.is_empty());
    }
}
