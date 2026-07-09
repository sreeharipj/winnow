/// Independent non-panic author-data factor (architecture §6, §7.C).
///
/// unhusk's `--json` contract only carries panic-path strings (anchor_files);
/// it does not expose the addresses of non-panic author-region strings
/// (C2 hosts, mutex names, ransom text, custom format strings) — architecture
/// §9's honest seam. Winnow recovers these itself by re-deriving the same
/// `(LEA [rip+rodata], MOV reg, imm)` pairing unhusk's own `types.rs` uses for
/// `#[derive(Debug)]` identifier recovery, but widened from "looks like an
/// identifier" to "printable ASCII of plausible string length" — behavioral
/// strings (URLs, hosts, ransom text) don't have identifier shape.
///
/// This module only *harvests candidates*. Independence (§6: these must not
/// be panic-path strings under another name) and rarity (§7.C: only worth
/// including if unlikely to appear benignly) are enforced by the caller
/// (main.rs) against the panic-string set and the benign corpus respectively.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::elfview::Section;

const MIN_LEN: usize = 6;
const MAX_LEN: usize = 200;

#[derive(Debug, Clone)]
pub struct BehaviorString {
    pub fn_start: u64,
    pub text: String,
}

pub fn extract_behavior_strings(
    text: &Section,
    rodata: &Section,
    fn_start: u64,
    fn_end: u64,
) -> Vec<BehaviorString> {
    let Some(fn_bytes) = text.slice_at(fn_start, (fn_end - fn_start) as usize) else {
        return Vec::new();
    };

    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut out = Vec::new();

    // (rodata address, ip the very next instruction must have). Rust's
    // fat-pointer construction emits `lea reg,[rip+STR]; mov reg2, LEN`
    // back-to-back for one string literal. unhusk's own identifier-only scan
    // (types.rs) tries every LEA in a lookback window because its
    // identifier-shape + boundary checks reject bad pairings; general
    // printable-ASCII text has no such guard rail, so a stale LEA paired
    // with an unrelated later MOV just re-slices the same byte blob at the
    // wrong length — producing overlapping garbage substrings of one real
    // string. Requiring strict, zero-gap adjacency is the principled fix.
    let mut pending_lea: Option<(u64, u64)> = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let mut set_new = false;

        if instr.mnemonic() == Mnemonic::Lea && instr.memory_base() == Register::RIP {
            let ea = instr.memory_displacement64();
            if rodata.contains_vaddr(ea) {
                pending_lea = Some((ea, instr.next_ip()));
                set_new = true;
            }
        }

        if instr.mnemonic() == Mnemonic::Mov {
            if let Some((rodata_vaddr, expected_ip)) = pending_lea {
                if instr.ip() == expected_ip {
                    let imm: u64 = match instr.op_kind(1) {
                        OpKind::Immediate8 => instr.immediate8() as u64,
                        OpKind::Immediate16 => instr.immediate16() as u64,
                        OpKind::Immediate32 => instr.immediate32() as u64,
                        OpKind::Immediate64 => instr.immediate64(),
                        OpKind::Immediate8to32 => instr.immediate8to32() as u64,
                        OpKind::Immediate8to64 => instr.immediate8to64() as u64,
                        OpKind::Immediate32to64 => instr.immediate32to64() as u64,
                        _ => 0,
                    };
                    if (MIN_LEN as u64..=MAX_LEN as u64).contains(&imm) {
                        if let Some(s) = try_extract_string(rodata, rodata_vaddr, imm as usize) {
                            out.push(BehaviorString { fn_start, text: s });
                        }
                    }
                }
            }
        }

        if !set_new {
            pending_lea = None;
        }
    }

    out
}

fn try_extract_string(rodata: &Section, vaddr: u64, len: usize) -> Option<String> {
    let bytes = rodata.slice_at(vaddr, len)?;
    if !bytes.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    // Panic-path strings are the confirming factor (architecture §6), not
    // independent — exclude anything that looks like a source path so the
    // two factors never overlap.
    if s.ends_with(".rs") || s.contains("src/") {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elfview::Section;

    const FN_START: u64 = 0x1000;

    /// `lea reg, [rip+disp32]` targeting `target_vaddr`, given the address
    /// (`next_ip`) of the instruction immediately after it.
    fn lea_bytes(target_vaddr: u64, next_ip: u64) -> [u8; 7] {
        let disp = (target_vaddr as i64 - next_ip as i64) as i32;
        let d = disp.to_le_bytes();
        [0x48, 0x8D, 0x05, d[0], d[1], d[2], d[3]]
    }

    /// `mov edx, imm32` — the length half of Rust's fat-pointer pairing.
    fn mov_edx_imm32(len: u32) -> [u8; 5] {
        let b = len.to_le_bytes();
        [0xBA, b[0], b[1], b[2], b[3]]
    }

    fn text_section(bytes: &[u8]) -> Section {
        Section {
            vaddr: FN_START,
            data: bytes.to_vec(),
        }
    }

    fn rodata_section(vaddr: u64, data: &[u8]) -> Section {
        Section {
            vaddr,
            data: data.to_vec(),
        }
    }

    #[test]
    fn extracts_string_from_zero_gap_lea_mov_pair() {
        let rodata_vaddr = 0x2000;
        let s = b"hello world";
        let lea = lea_bytes(rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(s.len() as u32);
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "hello world");
        assert_eq!(found[0].fn_start, FN_START);
    }

    #[test]
    fn does_not_splice_across_a_gap_between_lea_and_mov() {
        // Regression test for the fixed bug: an earlier version paired any
        // LEA in a lookback window with a later MOV and spliced unrelated
        // bytes together. One instruction between the two must now
        // suppress extraction entirely.
        let rodata_vaddr = 0x2000;
        let s = b"hello world";
        let lea = lea_bytes(rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(s.len() as u32);
        let mut fn_bytes = lea.to_vec();
        fn_bytes.push(0x90); // nop — breaks zero-gap adjacency
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }

    #[test]
    fn excludes_strings_that_look_like_source_paths() {
        let rodata_vaddr = 0x2000;
        let s = b"src/main.rs"; // 11 bytes — same length as the positive case
        let lea = lea_bytes(rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(s.len() as u32);
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }

    #[test]
    fn rejects_length_below_minimum() {
        let rodata_vaddr = 0x2000;
        let lea = lea_bytes(rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(3); // below MIN_LEN, must short-circuit
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, &[]); // nothing valid to read

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }
}
