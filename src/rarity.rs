/// Discriminative-substring reduction against the benign corpus (architecture
/// §7.C rarity filter for non-panic strings; critique finding 2's demand that
/// masked-hex specificity be *measured* against a background set, not
/// asserted). This is the module that only exists because Phase 0 built the
/// corpus first — the whole reason this project is ordered the way it is.
use std::path::Path;

use anyhow::{Context, Result};

use crate::mask::{MaskByte, MaskedAtom};

pub struct Corpus {
    files: Vec<(String, Vec<u8>)>,
}

impl Corpus {
    pub fn load(dir: &Path) -> Result<Self> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let data = std::fs::read(entry.path())?;
            files.push((entry.file_name().to_string_lossy().to_string(), data));
        }
        Ok(Self { files })
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// A string is "rare" (architecture §7.C) if it appears in none of the
    /// benign corpus files.
    pub fn string_is_rare(&self, s: &str) -> bool {
        let needle = s.as_bytes();
        !self
            .files
            .iter()
            .any(|(_, data)| contains_subslice(data, needle))
    }

    /// Names of corpus files a masked-hex atom collides with. Empty = the
    /// atom is discriminative against this corpus (critique finding 2's
    /// substring-reduction check, done empirically rather than assumed).
    pub fn masked_atom_collisions(&self, atom: &MaskedAtom) -> Vec<String> {
        self.files
            .iter()
            .filter(|(_, data)| masked_match_anywhere(data, &atom.bytes))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Wildcard-aware substring search. Anchors on the first exact byte in the
/// pattern so a random binary's bytes rarely reach the full per-position
/// comparison — without this, an ~11KB masked-function atom against a
/// multi-MB corpus file is prohibitively slow.
fn masked_match_anywhere(hay: &[u8], pat: &[MaskByte]) -> bool {
    if pat.is_empty() || pat.len() > hay.len() {
        return false;
    }
    let Some((anchor_idx, anchor_byte)) = pat.iter().enumerate().find_map(|(i, b)| match b {
        MaskByte::Exact(v) => Some((i, *v)),
        MaskByte::Wildcard => None,
    }) else {
        // All-wildcard pattern can't discriminate anything; treat as no match
        // rather than a trivial match-everything.
        return false;
    };

    let last_start = hay.len() - pat.len();
    'outer: for start in 0..=last_start {
        if hay[start + anchor_idx] != anchor_byte {
            continue;
        }
        for (i, pb) in pat.iter().enumerate() {
            if let MaskByte::Exact(b) = pb {
                if hay[start + i] != *b {
                    continue 'outer;
                }
            }
        }
        return true;
    }
    false
}
