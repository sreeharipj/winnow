/// Per-function masked hex — the Tier 1 code factor. Masks only provably
/// volatile bytes, keeping everything else exact:
///   1. RIP-relative displacements,
///   2. 64-bit absolute immediates (`movabs`),
///   3. near-branch displacements (`call`/`jmp`/`jcc`, rel8 or rel32), whose
///      target shifts across recompiles, and
///   4. any range a real `.rela.dyn` `R_X86_64_RELATIVE` entry patches.
/// Ordinary stack displacements and small (non-branch) immediates are left exact.
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

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
    #[allow(dead_code)] // used by tests; emission path reports exact-byte counts
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

        // 3. Near-branch displacement (call/jmp/jcc, rel8 or rel32). iced-x86
        //    reports the rel as the instruction's immediate — not a
        //    displacement — and the target moves across recompiles, so those
        //    bytes are volatile and must be masked.
        if co.has_immediate() && is_near_branch(&instr) {
            mask_range(&mut out, instr_start, co.immediate_offset(), co.immediate_size());
        }
    }

    // 4. Any range a real R_X86_64_RELATIVE entry patches (8 bytes each),
    //    applied directly over the function's byte range. Keeping this out of
    //    the decode loop makes it independent of where the linear sweep landed
    //    and fully covers an 8-byte value that straddles an instruction split.
    let out_len = out.len();
    for r in rela {
        if r.offset >= fn_start && r.offset < fn_end {
            let off = (r.offset - fn_start) as usize;
            mask_range(&mut out, off, 0, 8.min(out_len - off));
        }
    }

    Some(MaskedAtom {
        fn_start,
        bytes: out,
    })
}

/// A direct near branch (`call`/`jmp`/`jcc`), whose sole operand is a
/// self-relative target. Indirect branches carry no immediate to mask.
fn is_near_branch(instr: &Instruction) -> bool {
    matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

fn mask_range(out: &mut [MaskByte], instr_start: usize, rel_off: usize, size: usize) {
    let len = out.len();
    let start = (instr_start + rel_off).min(len);
    let end = (start + size).min(len);
    for b in &mut out[start..end] {
        *b = MaskByte::Wildcard;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elfview::{RelaRelative, Section};

    fn text_section(fn_start: u64, bytes: Vec<u8>) -> Section {
        Section {
            vaddr: fn_start,
            data: bytes,
        }
    }

    #[test]
    fn wildcard_count_counts_only_wildcards() {
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![MaskByte::Exact(1), MaskByte::Wildcard, MaskByte::Wildcard],
        };
        assert_eq!(atom.wildcard_count(), 2);
    }

    #[test]
    fn masks_rip_relative_displacement_only() {
        // lea rax, [rip+0x10]
        let bytes = vec![0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let fn_start = 0x1000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0x48));
        assert_eq!(atom.bytes[1], MaskByte::Exact(0x8D));
        assert_eq!(atom.bytes[2], MaskByte::Exact(0x05));
        for b in &atom.bytes[3..7] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
    }

    #[test]
    fn masks_64_bit_absolute_immediate() {
        // movabs rax, 0x1122334455667788
        let mut bytes = vec![0x48, 0xB8];
        bytes.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
        let fn_start = 0x2000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0x48));
        assert_eq!(atom.bytes[1], MaskByte::Exact(0xB8));
        for b in &atom.bytes[2..10] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
    }

    #[test]
    fn masks_bytes_a_relocation_actually_patches() {
        // mov eax, 0x11223344 — a plain 32-bit immediate that rules 1/2
        // wouldn't otherwise touch, but a .rela.dyn entry says load-time
        // patches the byte at fn_start+1 (the start of the immediate).
        let bytes = vec![0xB8, 0x44, 0x33, 0x22, 0x11];
        let fn_start = 0x3000;
        let text = text_section(fn_start, bytes.clone());
        let rela = [RelaRelative {
            offset: fn_start + 1,
        }];
        let atom = mask_function(&text, &rela, fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0xB8));
        for b in &atom.bytes[1..5] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
    }

    #[test]
    fn masks_direct_call_rel32() {
        // call rel32 — opcode exact, the 4-byte displacement wildcarded.
        let bytes = vec![0xE8, 0x51, 0x07, 0x10, 0x00];
        let fn_start = 0x5000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0xE8));
        for b in &atom.bytes[1..5] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
    }

    #[test]
    fn masks_jmp_and_conditional_branch_rel32() {
        // jmp rel32 ; je rel32 (0F 84) — both displacements masked, both
        // opcodes (incl. the 0F 84 prefix) left exact.
        let mut bytes = vec![0xE9, 0x00, 0x01, 0x00, 0x00];
        bytes.extend_from_slice(&[0x0F, 0x84, 0x00, 0x02, 0x00, 0x00]);
        let fn_start = 0x6000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0xE9));
        for b in &atom.bytes[1..5] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
        assert_eq!(atom.bytes[5], MaskByte::Exact(0x0F));
        assert_eq!(atom.bytes[6], MaskByte::Exact(0x84));
        for b in &atom.bytes[7..11] {
            assert_eq!(*b, MaskByte::Wildcard);
        }
    }

    #[test]
    fn masks_short_branch_rel8() {
        // jmp rel8 ; je rel8 — single displacement byte each, opcodes exact.
        let bytes = vec![0xEB, 0x10, 0x74, 0x08];
        let fn_start = 0x7000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.bytes[0], MaskByte::Exact(0xEB));
        assert_eq!(atom.bytes[1], MaskByte::Wildcard);
        assert_eq!(atom.bytes[2], MaskByte::Exact(0x74));
        assert_eq!(atom.bytes[3], MaskByte::Wildcard);
    }

    #[test]
    fn monomorphized_copies_collapse_after_masking() {
        // Same instructions, different call targets — the akira fn 0xc805c vs
        // 0xc8116 case. After masking, the two atoms must be byte-identical.
        let prefix = [0x4C, 0x39, 0xE9]; // cmp rcx, r13 — exact, no operands to mask
        let mut a = prefix.to_vec();
        a.extend_from_slice(&[0xE8, 0x51, 0x07, 0x10, 0x00]); // call, target A
        let mut b = prefix.to_vec();
        b.extend_from_slice(&[0xE8, 0x97, 0x06, 0x10, 0x00]); // call, target B
        let fs = 0x8000;
        let atom_a = mask_function(&text_section(fs, a.clone()), &[], fs, fs + a.len() as u64).unwrap();
        let atom_b = mask_function(&text_section(fs, b.clone()), &[], fs, fs + b.len() as u64).unwrap();

        assert_ne!(a, b); // raw bytes differ...
        assert_eq!(atom_a.bytes, atom_b.bytes); // ...but masked atoms are identical
        assert_eq!(atom_a.wildcard_count(), 4); // exactly the 4 rel32 bytes
    }

    #[test]
    fn relocation_spanning_two_instructions_is_fully_masked() {
        // An 8-byte R_X86_64_RELATIVE value at fn_start+2 covers bytes [2..10),
        // straddling many single-byte instructions. All 8 must be masked — the
        // old per-instruction pass clamped to the one instruction at the offset
        // and left the other 7 exact.
        let bytes = vec![0x90u8; 12]; // 12 one-byte NOPs
        let fn_start = 0x9000;
        let text = text_section(fn_start, bytes.clone());
        let rela = [RelaRelative {
            offset: fn_start + 2,
        }];
        let atom = mask_function(&text, &rela, fn_start, fn_start + bytes.len() as u64).unwrap();

        for (i, b) in atom.bytes.iter().enumerate() {
            let expect_wild = (2..10).contains(&i);
            assert_eq!(matches!(b, MaskByte::Wildcard), expect_wild, "byte {i}");
        }
    }

    #[test]
    fn leaves_ordinary_stack_displacement_untouched() {
        // mov eax, [rbp-8] — stack-relative, no volatility, must stay exact.
        let bytes = vec![0x8B, 0x45, 0xF8];
        let fn_start = 0x4000;
        let text = text_section(fn_start, bytes.clone());
        let atom = mask_function(&text, &[], fn_start, fn_start + bytes.len() as u64).unwrap();

        assert_eq!(atom.wildcard_count(), 0);
        for (i, b) in atom.bytes.iter().enumerate() {
            assert_eq!(*b, MaskByte::Exact(bytes[i]));
        }
    }
}
