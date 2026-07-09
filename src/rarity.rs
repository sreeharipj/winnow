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

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(files: Vec<(&str, &[u8])>) -> Corpus {
        Corpus {
            files: files
                .into_iter()
                .map(|(n, d)| (n.to_string(), d.to_vec()))
                .collect(),
        }
    }

    #[test]
    fn contains_subslice_edge_cases() {
        assert!(!contains_subslice(b"abc", b"")); // empty needle never matches
        assert!(!contains_subslice(b"ab", b"abc")); // needle longer than haystack
        assert!(contains_subslice(b"abcdef", b"cde"));
    }

    #[test]
    fn string_is_rare_when_absent_from_every_file() {
        let c = corpus(vec![("a", b"hello world"), ("b", b"goodbye")]);
        assert!(c.string_is_rare("needle"));
    }

    #[test]
    fn string_is_not_rare_when_present_in_any_file() {
        let c = corpus(vec![("a", b"hello world"), ("b", b"goodbye")]);
        assert!(!c.string_is_rare("hello"));
    }

    #[test]
    fn masked_atom_collision_matches_through_wildcards() {
        // Pattern "AA ?? CC" must match "AA BB CC" even though the
        // wildcarded byte differs.
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![
                MaskByte::Exact(0xAA),
                MaskByte::Wildcard,
                MaskByte::Exact(0xCC),
            ],
        };
        let c = corpus(vec![("benign", &[0x00, 0xAA, 0xBB, 0xCC, 0x00])]);
        assert_eq!(c.masked_atom_collisions(&atom), vec!["benign".to_string()]);
    }

    #[test]
    fn masked_atom_no_collision_when_an_exact_byte_differs() {
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![
                MaskByte::Exact(0xAA),
                MaskByte::Wildcard,
                MaskByte::Exact(0xCC),
            ],
        };
        let c = corpus(vec![("benign", &[0xAA, 0xBB, 0xDD])]); // last byte differs
        assert!(c.masked_atom_collisions(&atom).is_empty());
    }

    #[test]
    fn all_wildcard_pattern_never_reports_a_collision() {
        // An atom with no exact anchor byte can't discriminate anything;
        // it must never be treated as match-everything.
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![MaskByte::Wildcard; 4],
        };
        let c = corpus(vec![("benign", &[0, 1, 2, 3, 4, 5])]);
        assert!(c.masked_atom_collisions(&atom).is_empty());
    }
}
