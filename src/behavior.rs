/// Independent non-panic author-data factor (architecture §6, §7.C).
///
/// unhusk's `--json` contract only carries panic-path strings (anchor_files);
/// it does not expose the addresses of non-panic author-region strings
/// (C2 hosts, mutex names, ransom text, custom format strings) — architecture
/// §9's honest seam. Winnow recovers these itself by re-deriving the
/// `(LEA [rip+rodata], <length>)` fat-pointer construction that Rust emits for
/// a `&str` literal, but widened from unhusk's "looks like an identifier" to
/// "printable ASCII of plausible string length" — behavioral strings (URLs,
/// hosts, ransom text) don't have identifier shape.
///
/// ## Why this is a dataflow scan, not adjacency
///
/// An earlier version required the length `mov` to be the *literal next*
/// instruction after the `lea`. Measured against three real samples (krusty,
/// akira_v2, blackcat_sphynx) that guard rejected 100% of candidates: not one
/// rodata-targeting `lea` in any STRONG function is immediately followed by a
/// `mov reg,imm`. Real rustc/LLVM codegen defeats strict adjacency three ways:
///
///   1. The length `mov` is separated from the `lea` by unrelated argument
///      setup — e.g. `lea rsi,[rip+STR]; lea rdi,[rsp+buf]; mov edx,LEN; call`
///      (blackcat's `esxcli ... vm process list`, len 83).
///   2. Small lengths are loaded with the size-optimized idiom `push imm8;
///      pop reg`, never a `mov` at all (akira's path/command fragments).
///   3. The length is stored as the length half of a `(ptr,len)` fat pointer
///      via `mov [mem], imm` when the slice is written into a struct/array.
///
/// So we scan a short forward window after each rodata `lea`, stopping the
/// moment the pointer register is redefined (this is what prevents a stale
/// `lea` from being paired with an unrelated later length — the splice bug the
/// old adjacency rule was really trying to avoid). The length is the first
/// in-range immediate assigned to a *different* register (or memory) inside
/// that window whose `rodata[target..target+len]` slice is exactly printable.
/// `.rodata` holds unterminated, back-to-back string bytes, so the exact
/// length is what carves out a stable logical string; a wrong length almost
/// always fails the printable-slice check.
///
/// This module only *harvests candidates*. Independence (§6: these must not
/// be panic-path strings under another name) and rarity (§7.C: only worth
/// including if unlikely to appear benignly) are enforced by the caller
/// (main.rs) against the panic-string set and the benign corpus respectively.
use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::elfview::Section;

const MIN_LEN: usize = 6;
const MAX_LEN: usize = 200;
/// How many instructions after a rodata `lea` we look for its length. Sized
/// from ground truth: the widest real gap observed (blackcat) is 2, so 8
/// leaves headroom for denser argument setup without wandering into the next
/// unrelated string construction (which a pointer-register redefinition ends
/// first anyway).
const WINDOW: usize = 8;

#[derive(Debug, Clone)]
pub struct BehaviorString {
    pub fn_start: u64,
    pub text: String,
}

/// One decoded instruction, reduced to the two things the pairing scan needs:
/// which pointer it loads (if any), what length immediate it defines (if any),
/// and which full registers it writes (for pointer-clobber detection).
struct Decoded {
    /// `Some((ptr_full_reg, rodata_target))` for a `lea reg,[rip+X]` whose X
    /// lands in `.rodata`.
    lea_target: Option<(Register, u64)>,
    len_src: Option<LenSrc>,
    /// Full (64-bit) registers this instruction writes.
    writes: Vec<Register>,
}

enum LenSrc {
    /// `mov reg, imm` — reg carries the length.
    RegImm { dest_full: Register, imm: u64 },
    /// `mov [mem], imm` — the length half of a fat pointer stored to memory.
    MemImm { imm: u64 },
    /// `push imm` — pairs with a following `pop reg`.
    PushImm { imm: u64 },
    /// `pop reg` — consumes a pending `push imm` as the length.
    Pop { dest_full: Register },
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

    let decoded = decode_function(fn_bytes, fn_start, rodata);
    let mut out = Vec::new();

    for (i, d) in decoded.iter().enumerate() {
        let Some((ptr_full, target)) = d.lea_target else {
            continue;
        };

        let mut pending_push: Option<u64> = None;
        let end = (i + 1 + WINDOW).min(decoded.len());
        for w in &decoded[i + 1..end] {
            // The pointer register is redefined: any length past this point
            // belongs to a different string. Stop before mis-pairing.
            if w.writes.iter().any(|r| *r == ptr_full) {
                break;
            }

            let mut candidate: Option<u64> = None;
            match &w.len_src {
                Some(LenSrc::RegImm { dest_full, imm }) if *dest_full != ptr_full => {
                    candidate = Some(*imm);
                }
                Some(LenSrc::MemImm { imm }) => candidate = Some(*imm),
                Some(LenSrc::PushImm { imm }) => {
                    pending_push = Some(*imm);
                    continue;
                }
                Some(LenSrc::Pop { dest_full }) => {
                    if let Some(v) = pending_push.take() {
                        if *dest_full != ptr_full {
                            candidate = Some(v);
                        }
                    }
                }
                _ => {}
            }
            // A `push` was the only thing that kept a pending length alive; any
            // other instruction breaks the strict push/pop adjacency codegen
            // actually emits.
            pending_push = None;

            if let Some(len) = candidate {
                let len = len as usize;
                if (MIN_LEN..=MAX_LEN).contains(&len) {
                    if let Some(s) = try_extract_string(rodata, target, len) {
                        out.push(BehaviorString {
                            fn_start,
                            text: s,
                        });
                        break;
                    }
                }
            }
        }
    }

    out
}

fn decode_function(fn_bytes: &[u8], fn_start: u64, rodata: &Section) -> Vec<Decoded> {
    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut info_factory = InstructionInfoFactory::new();
    let mut out = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);

        let lea_target = if instr.mnemonic() == Mnemonic::Lea
            && instr.memory_base() == Register::RIP
        {
            let ea = instr.memory_displacement64();
            if rodata.contains_vaddr(ea) {
                Some((instr.op0_register().full_register(), ea))
            } else {
                None
            }
        } else {
            None
        };

        let len_src = classify_len_src(&instr);

        let info = info_factory.info(&instr);
        let writes: Vec<Register> = info
            .used_registers()
            .iter()
            .filter(|u| {
                matches!(
                    u.access(),
                    OpAccess::Write
                        | OpAccess::ReadWrite
                        | OpAccess::CondWrite
                        | OpAccess::ReadCondWrite
                )
            })
            .map(|u| u.register().full_register())
            .collect();

        out.push(Decoded {
            lea_target,
            len_src,
            writes,
        });
    }

    out
}

fn classify_len_src(instr: &Instruction) -> Option<LenSrc> {
    match instr.mnemonic() {
        Mnemonic::Push => imm_at(instr, 0).map(|imm| LenSrc::PushImm { imm }),
        Mnemonic::Pop if instr.op0_kind() == OpKind::Register => Some(LenSrc::Pop {
            dest_full: instr.op0_register().full_register(),
        }),
        Mnemonic::Mov => match instr.op0_kind() {
            OpKind::Register => imm_at(instr, 1).map(|imm| LenSrc::RegImm {
                dest_full: instr.op0_register().full_register(),
                imm,
            }),
            OpKind::Memory => imm_at(instr, 1).map(|imm| LenSrc::MemImm { imm }),
            _ => None,
        },
        _ => None,
    }
}

/// Value of an immediate operand, normalized to u64. Small positive lengths
/// are what we care about, so sign-extended forms are fine (out-of-range
/// values are filtered by the length check).
fn imm_at(instr: &Instruction, op: u32) -> Option<u64> {
    match instr.op_kind(op) {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        OpKind::Immediate8to16 => Some(instr.immediate8to16() as u16 as u64),
        OpKind::Immediate8to32 => Some(instr.immediate8to32() as u32 as u64),
        OpKind::Immediate8to64 => Some(instr.immediate8to64() as u64),
        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u64),
        _ => None,
    }
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

    /// `lea <reg>, [rip+disp32]` targeting `target_vaddr`, given the address
    /// (`next_ip`) of the instruction immediately after it. `reg_field` is the
    /// ModR/M reg number (rax=0, rcx=1, rdx=2, rsi=6).
    fn lea_bytes(reg_field: u8, target_vaddr: u64, next_ip: u64) -> [u8; 7] {
        let disp = (target_vaddr as i64 - next_ip as i64) as i32;
        let d = disp.to_le_bytes();
        let modrm = (reg_field << 3) | 0x05;
        [0x48, 0x8D, modrm, d[0], d[1], d[2], d[3]]
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
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7); // lea rax
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
    fn extracts_across_unrelated_arg_setup_gap() {
        // The blackcat pattern: `lea rsi,[rip+STR]; lea rdi,[rsp+buf];
        // mov edx,LEN`. The length is two instructions past the string lea,
        // separated by an unrelated argument-setup lea. Strict adjacency
        // rejected this; the windowed scan must recover it.
        let rodata_vaddr = 0x2000;
        let s = b"hello world";
        let lea_str = lea_bytes(6, rodata_vaddr, FN_START + 7); // lea rsi
        let lea_buf = [0x48, 0x8D, 0x7C, 0x24, 0x08]; // lea rdi,[rsp+0x8]
        let mov = mov_edx_imm32(s.len() as u32);
        let mut fn_bytes = lea_str.to_vec();
        fn_bytes.extend_from_slice(&lea_buf);
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "hello world");
    }

    #[test]
    fn extracts_length_from_push_pop_idiom() {
        // The akira/krusty pattern: length loaded with `push imm8; pop reg`
        // rather than a `mov reg,imm`. `mov`-only pairing never sees it.
        let rodata_vaddr = 0x2000;
        let s = b"hello world"; // len 11 = 0x0B
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7); // lea rax
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&[0x6A, 0x0B]); // push 0x0B
        fn_bytes.push(0x5A); // pop rdx
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "hello world");
    }

    #[test]
    fn does_not_pair_after_pointer_register_is_clobbered() {
        // Regression guard for the stale-lea splice bug, re-expressed for the
        // windowed scan: once the pointer register (rax) is overwritten, a
        // later length must not be paired with the dead pointer.
        let rodata_vaddr = 0x2000;
        let s = b"hello world";
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7); // lea rax
        let clobber = [0x48, 0x89, 0xF0]; // mov rax, rsi  (rax redefined)
        let mov = mov_edx_imm32(s.len() as u32);
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&clobber);
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, s);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }

    #[test]
    fn does_not_pair_beyond_the_window() {
        // A length that only appears far past the window must not be paired,
        // even with the pointer register still live.
        let rodata_vaddr = 0x2000;
        let s = b"hello world";
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7); // lea rax
        let mut fn_bytes = lea.to_vec();
        for _ in 0..WINDOW {
            fn_bytes.push(0x90); // nop padding past the window
        }
        fn_bytes.extend_from_slice(&mov_edx_imm32(s.len() as u32));
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
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7);
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
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(3); // below MIN_LEN, must short-circuit
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, &[]); // nothing valid to read

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }

    #[test]
    fn rejects_non_printable_slice() {
        // A length in range but a slice with a non-printable byte is not a
        // string — the exact-printable check is what guards against wrong
        // lengths carving garbage out of the concatenated rodata blob.
        let rodata_vaddr = 0x2000;
        let data = b"hello\x00world"; // NUL in the middle
        let lea = lea_bytes(0, rodata_vaddr, FN_START + 7);
        let mov = mov_edx_imm32(11);
        let mut fn_bytes = lea.to_vec();
        fn_bytes.extend_from_slice(&mov);
        let fn_end = FN_START + fn_bytes.len() as u64;

        let text = text_section(&fn_bytes);
        let rodata = rodata_section(rodata_vaddr, data);

        let found = extract_behavior_strings(&text, &rodata, FN_START, fn_end);
        assert!(found.is_empty());
    }
}
