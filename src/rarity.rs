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
            // `Path::is_file` follows symlinks, so a corpus directory built
            // from symlinks (as the A/B holdout split is) loads correctly;
            // `entry.file_type()` would report the symlink itself and skip it.
            if !entry.path().is_file() {
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
    /// atom is discriminative against this corpus. Retained as a diagnostic
    /// (and exercised by tests); the emission path uses [`Corpus::reduce_atom`].
    #[allow(dead_code)]
    pub fn masked_atom_collisions(&self, atom: &MaskedAtom) -> Vec<String> {
        self.files
            .iter()
            .filter(|(_, data)| masked_match_anywhere(data, &atom.bytes))
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn any_file_matches(&self, pat: &[MaskByte]) -> bool {
        self.files
            .iter()
            .any(|(_, data)| masked_match_anywhere(data, pat))
    }

    /// Discriminative-substring *reduction* (architecture §7.B, critique
    /// finding 2), done for real rather than asserted.
    ///
    /// The maximal atom — a whole masked function, hundreds to tens of
    /// thousands of bytes — is trivially absent from any benign file, so
    /// checking *it* for collisions stamps every atom "discriminative" for
    /// free and proves nothing. The honest question is how *little* byte
    /// specificity the corpus actually demands: we reduce the atom to its most
    /// exact-byte-dense [`REDUCED_LEN`]-byte window and check *that*, where a
    /// benign collision is genuinely possible. Candidate windows are tried
    /// strongest-first (most exact bytes), so the first collision-free hit is
    /// also the most discriminative. `None` means no window with at least
    /// [`MIN_EXACT`] exact bytes is free of benign collisions — the function's
    /// code is not discriminative at this granularity and the caller drops it.
    pub fn reduce_atom(&self, atom: &MaskedAtom) -> Option<ReducedAtom> {
        let n = atom.bytes.len();
        let win_len = REDUCED_LEN.min(n);

        let mut candidates: Vec<(usize, usize)> = (0..=(n - win_len))
            .map(|off| (off, count_exact(&atom.bytes[off..off + win_len])))
            .filter(|(_, exact)| *exact >= MIN_EXACT)
            .collect();
        // Most exact bytes first: the strongest window that survives the corpus
        // is the one we want to emit.
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        for (off, exact) in candidates {
            let win = &atom.bytes[off..off + win_len];
            if !self.any_file_matches(win) {
                return Some(ReducedAtom {
                    start_offset: off,
                    orig_len: n,
                    exact_bytes: exact,
                    bytes: win.to_vec(),
                });
            }
        }
        None
    }
}

/// Target length of a reduced atom. 64 bytes of mostly-exact machine code is
/// specific enough that a benign collision is near-impossible in practice, yet
/// short enough to survive an instruction edit elsewhere in the function —
/// unlike the whole-function maximal atom, which any single change breaks.
pub const REDUCED_LEN: usize = 64;
/// A window must carry at least this many exact (non-wildcard) bytes to count
/// as discriminative; a heavily relocation-masked window is mostly `??` and
/// says little about the code.
const MIN_EXACT: usize = 16;

/// A masked atom reduced to a discriminative window (see [`Corpus::reduce_atom`]).
#[derive(Debug, Clone)]
pub struct ReducedAtom {
    /// Offset of the window within the original maximal atom.
    pub start_offset: usize,
    /// Length of the original maximal (whole-function) atom.
    pub orig_len: usize,
    /// Exact (non-wildcard) byte count in the emitted window.
    pub exact_bytes: usize,
    pub bytes: Vec<MaskByte>,
}

fn count_exact(win: &[MaskByte]) -> usize {
    win.iter().filter(|b| matches!(b, MaskByte::Exact(_))).count()
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    // SIMD substring search (Two-Way + memchr prefilter). The corpus is ~1.5GB
    // and `string_is_rare` scans all of it per candidate string; the old
    // `hay.windows(n).any(|w| w == needle)` ran at ~460 MB/s (a naive
    // byte-by-byte compare at every offset), memmem clears ~37 GB/s on the same
    // data — an ~80x speedup, measured, for identical results.
    memchr::memmem::find(hay, needle).is_some()
}

/// Wildcard-aware substring search. Anchors on the first exact byte in the
/// pattern so a random binary's bytes rarely reach the full per-position
/// comparison — without this, an ~11KB masked-function atom against a
/// multi-MB corpus file is prohibitively slow.
///
/// The anchor-byte hunt itself is delegated to `memchr` (SIMD) rather than the
/// old byte-at-a-time `for start in 0..=last_start` scan: on the ~1.5GB corpus
/// that lifted this primitive from ~2.0 GB/s to ~19 GB/s (~10x), measured, for
/// identical results. Only positions where the anchor byte actually lands pay
/// for the full per-position wildcard comparison.
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

    // A candidate window starts at hay index `start` (0..=last_start), and its
    // anchor byte sits at `start + anchor_idx`. So the anchor can only legally
    // occur within hay[anchor_idx ..= anchor_idx + last_start]; each memchr hit
    // at scan-relative `start` is a window whose anchor already matches.
    let last_start = hay.len() - pat.len();
    let scan = &hay[anchor_idx..=anchor_idx + last_start];
    for start in memchr::memchr_iter(anchor_byte, scan) {
        let matches = pat.iter().enumerate().all(|(i, pb)| match pb {
            MaskByte::Exact(b) => hay[start + i] == *b,
            MaskByte::Wildcard => true,
        });
        if matches {
            return true;
        }
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

    fn exact_atom(bytes: &[u8]) -> MaskedAtom {
        MaskedAtom {
            fn_start: 0,
            bytes: bytes.iter().map(|&b| MaskByte::Exact(b)).collect(),
        }
    }

    #[test]
    fn reduce_atom_shrinks_to_a_discriminative_window() {
        let atom = exact_atom(&(0u8..100).collect::<Vec<_>>());
        // Corpus shares nothing with the atom's byte range.
        let c = corpus(vec![("benign", &[0xEE; 4096])]);
        let r = c.reduce_atom(&atom).expect("a clean window exists");
        assert_eq!(r.orig_len, 100);
        assert_eq!(r.bytes.len(), REDUCED_LEN); // reduced from 100 → 64
        assert_eq!(r.exact_bytes, REDUCED_LEN); // all exact in this atom
    }

    #[test]
    fn reduce_atom_drops_when_every_window_collides() {
        let seq: Vec<u8> = (0u8..100).collect();
        let atom = exact_atom(&seq);
        // The whole atom is present in a benign file, so every 64-byte window
        // is a substring of it → all collide → not discriminative.
        let c = corpus(vec![("benign", &seq)]);
        assert!(c.reduce_atom(&atom).is_none());
    }

    #[test]
    fn reduce_atom_keeps_a_short_atom_whole() {
        let atom = exact_atom(&(0u8..40).collect::<Vec<_>>()); // shorter than REDUCED_LEN
        let c = corpus(vec![("benign", &[0xEE; 256])]);
        let r = c.reduce_atom(&atom).expect("clean");
        assert_eq!(r.bytes.len(), 40);
        assert_eq!(r.start_offset, 0);
    }

    #[test]
    fn reduce_atom_drops_a_mostly_wildcard_atom() {
        // 100 bytes, only 10 exact — no 64-byte window reaches MIN_EXACT.
        let mut bytes = vec![MaskByte::Wildcard; 100];
        for b in bytes.iter_mut().take(10) {
            *b = MaskByte::Exact(0x42);
        }
        let atom = MaskedAtom { fn_start: 0, bytes };
        let c = corpus(vec![("benign", &[0xEE; 256])]);
        assert!(c.reduce_atom(&atom).is_none());
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
