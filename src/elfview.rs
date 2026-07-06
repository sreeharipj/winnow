/// Winnow's own ELF re-open (architecture §9: the JSON contract carries no
/// bytes, so the consumer re-parses the binary the producer already parsed).
/// Deliberately thin — Phase 1 only needs `.text` for the code signal;
/// `.rodata` / `.data.rel.ro` are for the non-panic author-string factor,
/// which is DEFERRED to Phase 3 (see src/main.rs).
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection};

pub struct Section {
    pub vaddr: u64,
    pub data: Vec<u8>,
}

impl Section {
    pub fn slice_at(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let off = vaddr.checked_sub(self.vaddr)? as usize;
        self.data.get(off..off.checked_add(len)?)
    }

    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr < self.vaddr + self.data.len() as u64
    }
}

/// A single `R_X86_64_RELATIVE` entry from `.rela.dyn` (mirrors unhusk's
/// `src/elf.rs`): on-disk bytes at `offset` are pre-relocation placeholders;
/// the dynamic linker writes `addend` there at load time. Phase 3 uses this
/// defensively to mask any code byte that a relocation actually patches —
/// in practice these almost always land in `.data.rel.ro`, not `.text`
/// (near-CALL rel32 and RIP-relative LEA displacements are link-time
/// constants, already position-independent by construction), but checking
/// real relocation records is cheap and evidence-based rather than assumed.
#[derive(Debug, Clone, Copy)]
pub struct RelaRelative {
    pub offset: u64,
}

pub struct ParsedElf {
    sections: HashMap<String, Section>,
    pub rela_relative: Vec<RelaRelative>,
}

impl ParsedElf {
    pub fn load(path: &Path) -> Result<Self> {
        let buf = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let obj = object::File::parse(&*buf)
            .with_context(|| format!("parsing ELF {}", path.display()))?;

        let mut sections = HashMap::new();
        for name in [".text", ".rodata", ".data.rel.ro", ".rela.dyn"] {
            if let Some(sec) = obj.section_by_name(name) {
                if let Ok(data) = sec.uncompressed_data() {
                    sections.insert(
                        name.to_string(),
                        Section {
                            vaddr: sec.address(),
                            data: data.into_owned(),
                        },
                    );
                }
            }
        }
        let rela_relative = sections
            .get(".rela.dyn")
            .map(|s| parse_rela_relative(&s.data))
            .unwrap_or_default();
        Ok(Self {
            sections,
            rela_relative,
        })
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.get(name)
    }
}

/// Elf64_Rela is 24 bytes: r_offset(8) | r_info(8) | r_addend(8).
/// R_X86_64_RELATIVE = type 8: *(r_offset) = base + r_addend.
fn parse_rela_relative(data: &[u8]) -> Vec<RelaRelative> {
    const RELA_SZ: usize = 24;
    const R_X86_64_RELATIVE: u32 = 8;
    let mut out = Vec::new();
    for chunk in data.chunks_exact(RELA_SZ) {
        let r_offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let r_info = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let r_type = (r_info & 0xffff_ffff) as u32;
        if r_type == R_X86_64_RELATIVE {
            out.push(RelaRelative { offset: r_offset });
        }
    }
    out
}
