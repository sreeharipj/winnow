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
}

pub struct ParsedElf {
    sections: HashMap<String, Section>,
}

impl ParsedElf {
    pub fn load(path: &Path) -> Result<Self> {
        let buf = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let obj = object::File::parse(&*buf)
            .with_context(|| format!("parsing ELF {}", path.display()))?;

        let mut sections = HashMap::new();
        for name in [".text", ".rodata", ".data.rel.ro"] {
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
        Ok(Self { sections })
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.get(name)
    }
}
