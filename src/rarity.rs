/// Measures candidate signatures against the benign corpus: string rarity and
/// discriminative-substring reduction of masked-hex atoms.
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
            // `Path::is_file` follows symlinks, so a symlink-built corpus (the
            // A/B holdout split) loads correctly; `file_type()` would skip it.
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

    /// Names of corpus files a masked-hex atom collides with (empty = discriminative).
    /// A diagnostic exercised by tests; the emission path uses [`Corpus::reduce_atom`].
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

    /// Reduce a masked atom to its most exact-byte-dense [`REDUCED_LEN`]-byte
    /// window that is free of benign collisions. The whole-function atom is
    /// trivially collision-free and proves nothing, so we test the reduced
    /// window where a collision is actually possible. Windows are tried
    /// strongest-first, so the first survivor is the most discriminative.
    /// `None` = no window with ≥ [`MIN_EXACT`] exact bytes survives; caller drops it.
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

/// Reduced-atom length: 64 bytes of mostly-exact code is specific enough that a
/// benign collision is near-impossible, yet short enough to survive an edit
/// elsewhere in the function.
pub const REDUCED_LEN: usize = 64;
/// Minimum exact (non-wildcard) bytes for a window to count as discriminative.
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
    // SIMD substring search; ~80x over `windows().any()` on the ~1.5GB corpus.
    memchr::memmem::find(hay, needle).is_some()
}

/// Wildcard-aware substring search: is `pat` present anywhere in `hay`, with
/// `MaskByte::Wildcard` matching any byte?
///
/// Prefilters on the pattern's longest contiguous run of exact bytes via
/// `memchr::memmem` (SIMD): any real match must contain that run, so memmem
/// enumerates candidate window starts and the full compare runs only there.
/// A run of a few exact bytes makes the scan memory-bound (~40 GB/s, measured).
/// An all-wildcard pattern discriminates nothing and never matches.
fn masked_match_anywhere(hay: &[u8], pat: &[MaskByte]) -> bool {
    if pat.is_empty() || pat.len() > hay.len() {
        return false;
    }
    let Some((run_off, run)) = longest_exact_run(pat) else {
        // All-wildcard pattern can't discriminate anything.
        return false;
    };

    let last_start = hay.len() - pat.len();
    let finder = memchr::memmem::Finder::new(&run);
    // Step one past each hit (not memmem's non-overlapping iterator): overlapping
    // run occurrences can each seed a distinct window start.
    let mut from = 0;
    while let Some(rel) = finder.find(&hay[from..]) {
        let hit = from + rel; // hay index where the run begins
        // The run sits at pat[run_off..], so the window starts at hit - run_off.
        if let Some(start) = hit.checked_sub(run_off) {
            if start <= last_start
                && pat.iter().enumerate().all(|(i, pb)| match pb {
                    MaskByte::Exact(b) => hay[start + i] == *b,
                    MaskByte::Wildcard => true,
                })
            {
                return true;
            }
        }
        from = hit + 1;
    }
    false
}

/// The longest contiguous run of `Exact` bytes in `pat`, as `(offset, bytes)`,
/// leftmost on ties; `None` iff `pat` is all wildcards.
fn longest_exact_run(pat: &[MaskByte]) -> Option<(usize, Vec<u8>)> {
    let mut best: Option<(usize, usize)> = None; // (start, len)
    let mut i = 0;
    while i < pat.len() {
        if matches!(pat[i], MaskByte::Exact(_)) {
            let start = i;
            while i < pat.len() && matches!(pat[i], MaskByte::Exact(_)) {
                i += 1;
            }
            let len = i - start;
            if best.is_none_or(|(_, best_len)| len > best_len) {
                best = Some((start, len));
            }
        } else {
            i += 1;
        }
    }
    best.map(|(start, len)| {
        let bytes = pat[start..start + len]
            .iter()
            .map(|b| match b {
                MaskByte::Exact(v) => *v,
                MaskByte::Wildcard => unreachable!("a run of Exact bytes has no wildcard"),
            })
            .collect();
        (start, bytes)
    })
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

    #[test]
    fn masked_atom_matches_when_longest_run_is_mid_pattern() {
        // Prefilter run "AA BB CC" sits at offset 2 (run_off = 2), with leading
        // and trailing wildcards. The compare must be anchored back to the
        // window start (hit - run_off), not the run itself.
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![
                MaskByte::Wildcard,
                MaskByte::Wildcard,
                MaskByte::Exact(0xAA),
                MaskByte::Exact(0xBB),
                MaskByte::Exact(0xCC),
                MaskByte::Wildcard,
            ],
        };
        let c = corpus(vec![("benign", &[0x11, 0x22, 0xAA, 0xBB, 0xCC, 0x33])]);
        assert_eq!(c.masked_atom_collisions(&atom), vec!["benign".to_string()]);
    }

    #[test]
    fn masked_atom_run_too_close_to_start_cannot_seed_a_window() {
        // Same pattern, but the run's only occurrence is at file index 0 — there
        // is no room for the two leading wildcard bytes, so window start would be
        // -2. The checked_sub(run_off) underflow guard must reject it.
        let atom = MaskedAtom {
            fn_start: 0,
            bytes: vec![
                MaskByte::Wildcard,
                MaskByte::Wildcard,
                MaskByte::Exact(0xAA),
                MaskByte::Exact(0xBB),
                MaskByte::Exact(0xCC),
                MaskByte::Wildcard,
            ],
        };
        let c = corpus(vec![("benign", &[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00])]);
        assert!(c.masked_atom_collisions(&atom).is_empty());
    }

    #[test]
    fn longest_exact_run_picks_the_longest_contiguous_run() {
        // runs: [0]=1, [2..4]=2, [6..9]=3 -> longest is the length-3 run at 6.
        let pat = vec![
            MaskByte::Exact(0x01),
            MaskByte::Wildcard,
            MaskByte::Exact(0x02),
            MaskByte::Exact(0x03),
            MaskByte::Wildcard,
            MaskByte::Wildcard,
            MaskByte::Exact(0x04),
            MaskByte::Exact(0x05),
            MaskByte::Exact(0x06),
        ];
        assert_eq!(longest_exact_run(&pat), Some((6, vec![0x04, 0x05, 0x06])));
    }

    #[test]
    fn longest_exact_run_is_none_for_all_wildcards() {
        assert_eq!(longest_exact_run(&[MaskByte::Wildcard; 5]), None);
    }
}
