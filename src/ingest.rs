/// Ingest & Evidence Census (architecture §7.A) — Phase 1 slice.
///
/// Winnow does not re-implement author-function attribution. It shells out to
/// `unhusk --precision --json <elf>` and consumes the JSON contract as-is:
/// `{binary, arch, min_anchors, functions:[{start,end,size,tier,anchor_count,
/// anchor_files}]}`. Boundaries, tiers, and panic source paths come from here;
/// raw bytes come from Winnow's own re-open of the ELF (see `elfview.rs`).
///
/// This is the subprocess+JSON seam the architecture doc (§3, §9) argues for,
/// not a path-dependency on unhusk's internals — the two projects communicate
/// only through this contract.
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Census {
    #[allow(dead_code)]
    pub binary: String,
    #[allow(dead_code)]
    pub arch: String,
    pub min_anchors: usize,
    pub functions: Vec<FnRange>,
}

#[derive(Debug, Deserialize)]
pub struct FnRange {
    #[serde(deserialize_with = "hex_u64")]
    pub start: u64,
    #[serde(deserialize_with = "hex_u64")]
    pub end: u64,
    #[allow(dead_code)]
    pub size: u64,
    pub tier: String,
    #[allow(dead_code)]
    pub anchor_count: usize,
    pub anchor_files: Vec<String>,
}

fn hex_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
}

/// Locate and run unhusk, preferring (in order): an explicit `--unhusk-bin`
/// override, PATH lookup, then the sibling-repo convention this project's
/// build spec assumes (`~/Videos/winnow` next to `~/Videos/unhusk`).
pub fn run_unhusk(elf_path: &Path, unhusk_bin: Option<&Path>) -> Result<Census> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = unhusk_bin {
        candidates.push(p.to_path_buf());
    }
    candidates.push(PathBuf::from("unhusk"));
    candidates.push(PathBuf::from("../unhusk/target/release/unhusk"));

    let mut last_err: Option<anyhow::Error> = None;
    for cand in &candidates {
        match Command::new(cand)
            .arg(elf_path)
            .arg("--precision")
            .arg("--json")
            .output()
        {
            Ok(out) if out.status.success() => {
                let census: Census = serde_json::from_slice(&out.stdout).with_context(|| {
                    format!("parsing unhusk JSON output for {}", elf_path.display())
                })?;
                return Ok(census);
            }
            Ok(out) => {
                last_err = Some(anyhow!(
                    "unhusk ({}) exited with {}: {}",
                    cand.display(),
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            Err(e) => {
                last_err = Some(anyhow!("could not spawn {}: {}", cand.display(), e));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not run unhusk (no candidates tried)")))
}
