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
