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
    // An explicit override is exclusive, not merely first-tried: silently
    // falling back to PATH/sibling after a user-specified binary fails would
    // mean winnow ran a *different* unhusk than the one asked for, which
    // defeats the point of pinning it (reproducibility is the whole reason
    // --unhusk-bin exists).
    let candidates: Vec<PathBuf> = match unhusk_bin {
        Some(p) => vec![p.to_path_buf()],
        None => vec![
            PathBuf::from("unhusk"),
            PathBuf::from("../unhusk/target/release/unhusk"),
        ],
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn hex_u64_parses_0x_prefixed_values() {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(deserialize_with = "hex_u64")] u64);
        let w: Wrapper = serde_json::from_str(r#""0x1a2b""#).unwrap();
        assert_eq!(w.0, 0x1a2b);
    }

    #[test]
    fn hex_u64_parses_values_without_prefix() {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(deserialize_with = "hex_u64")] u64);
        let w: Wrapper = serde_json::from_str(r#""ff""#).unwrap();
        assert_eq!(w.0, 0xff);
    }

    #[test]
    fn census_deserializes_the_unhusk_json_contract() {
        let json = r#"{
            "binary": "sample.elf",
            "arch": "x86-64",
            "min_anchors": 2,
            "functions": [
                {
                    "start": "0x1000",
                    "end": "0x1050",
                    "size": 80,
                    "tier": "strong",
                    "anchor_count": 1,
                    "anchor_files": ["src/main.rs"]
                }
            ]
        }"#;
        let census: Census = serde_json::from_str(json).unwrap();
        assert_eq!(census.min_anchors, 2);
        assert_eq!(census.functions.len(), 1);
        assert_eq!(census.functions[0].start, 0x1000);
        assert_eq!(census.functions[0].end, 0x1050);
        assert_eq!(census.functions[0].tier, "strong");
        assert_eq!(
            census.functions[0].anchor_files,
            vec!["src/main.rs".to_string()]
        );
    }

    /// Writes an executable stub standing in for `unhusk` so the
    /// subprocess+JSON seam (`run_unhusk`) can be exercised without the real
    /// binary installed. `tempfile` gives each call a guaranteed-unique path
    /// (no pid-reuse races) and deletes it on drop, even if the test panics.
    /// `into_temp_path()` closes our own write handle before returning —
    /// exec-ing a script we still hold open for writing is ETXTBSY.
    fn write_stub(script: &str) -> tempfile::TempPath {
        let mut f = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
        f.write_all(script.as_bytes()).unwrap();
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o755);
        f.as_file().set_permissions(perms).unwrap();
        f.into_temp_path()
    }

    /// Sandboxed/CI filesystems can intermittently return ETXTBSY when a
    /// just-written, just-chmod'd script is exec'd within milliseconds of
    /// being closed — a transient exec-after-write race in the filesystem
    /// layer, not a defect in `run_unhusk`. A real `unhusk` on PATH is never
    /// written moments before use, so this only bites this test's own setup;
    /// retrying the spawn a few times is the standard workaround.
    fn run_unhusk_retrying_exec_races(elf: &Path, bin: &tempfile::TempPath) -> Result<Census> {
        let mut last = None;
        for _ in 0..5 {
            match run_unhusk(elf, Some(bin)) {
                Err(e) if e.to_string().contains("Text file busy") => {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                other => return other,
            }
        }
        Err(last.unwrap())
    }

    #[test]
    fn run_unhusk_parses_stdout_json_on_success() {
        let stub = write_stub(
            "#!/bin/sh\necho '{\"binary\":\"x\",\"arch\":\"x86-64\",\"min_anchors\":1,\"functions\":[]}'\n",
        );

        let census =
            run_unhusk_retrying_exec_races(std::path::Path::new("/does/not/matter.elf"), &stub)
                .unwrap();
        assert_eq!(census.min_anchors, 1);
        assert!(census.functions.is_empty());
    }

    #[test]
    fn run_unhusk_surfaces_stderr_on_nonzero_exit() {
        let stub = write_stub("#!/bin/sh\necho 'boom' >&2\nexit 1\n");

        let err =
            run_unhusk_retrying_exec_races(std::path::Path::new("/does/not/matter.elf"), &stub)
                .unwrap_err();
        assert!(err.to_string().contains("boom"));
    }
}
