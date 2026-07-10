# Phase 3 — Tier 1 flagship attempt (filter corpus = held-out split A, 39 files)

Generated 2026-07-10T09:08:35Z. Rules are built against Corpus A only;
false positives are measured on the disjoint Corpus B (see results/fp_holdout.md).

## krusty_x
```
wrote /home/user/Videos/winnow/rules/krusty_x.yar (1 STRONG fns, 1 panic strings, 3 code atoms)
tier1 — measuring against benign corpus (39 files)
tier1 — masked atom for fn 0x2e70b reduced 11279B → 64B window at +0x0 (64 exact bytes, 0 corpus collisions)
tier1 — code factor: 1 atom(s) reduced & kept, 0 dropped as non-discriminative
tier1 — candidate behavioral string "called `Result::unwrap()` on an `Err` value" appears in the benign corpus, dropping it (not rare)
tier1 — candidate behavioral string "cannot access a Thread Local Storage value during or after destruction" appears in the benign corpus, dropping it (not rare)
TIER 1 NOT EARNED for 030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0 — 2 non-panic behavioral candidate(s) were harvested but none survived rarity filtering against the corpus. Tier 1 is the fortunate case (architecture §5); Tier 2 rule above still stands.
```

## akira_v2_x
```
wrote /home/user/Videos/winnow/rules/akira_v2_x.yar (7 STRONG fns, 4 panic strings, 21 code atoms)
tier1 — measuring against benign corpus (39 files)
tier1 — masked atom for fn 0xc805c reduced 186B → 64B window at +0x2b (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xc8116 reduced 186B → 64B window at +0x2b (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xc94ea reduced 220B → 64B window at +0x38 (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xd25af reduced 4854B → 64B window at +0xe7 (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xd38a5 reduced 2730B → 64B window at +0x47 (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xd434f reduced 28749B → 64B window at +0x0 (64 exact bytes, 0 corpus collisions)
tier1 — masked atom for fn 0xdc434 reduced 16747B → 64B window at +0xf5 (64 exact bytes, 0 corpus collisions)
tier1 — code factor: 7 atom(s) reduced & kept, 0 dropped as non-discriminative
tier1 — behavioral string "/akiranew.txt" (fn 0xd38a5) is rare — kept
tier1 — behavioral string "/altbootbank" (fn 0xd25af) is rare — kept
tier1 — candidate behavioral string "/lib64" appears in the benign corpus, dropping it (not rare)
tier1 — behavioral string "/locker" (fn 0xd25af) is rare — kept
tier1 — behavioral string "/lost+found" (fn 0xd25af) is rare — kept
tier1 — behavioral string "/productLocker" (fn 0xd25af) is rare — kept
tier1 — candidate behavioral string "/sys/fs/cgroup" appears in the benign corpus, dropping it (not rare)
tier1 — behavioral string "/tmp/stop_vms.sh" (fn 0xdc434) is rare — kept
tier1 — behavioral string "/vmfs/devices" (fn 0xd25af) is rare — kept
tier1 — behavioral string "/vmfs/volumes" (fn 0xd25af) is rare — kept
tier1 — behavioral string "/vmimages/" (fn 0xd25af) is rare — kept
tier1 — behavioral string "/vmupgrade" (fn 0xd25af) is rare — kept
tier1 — behavioral string "TODO: panic message" (fn 0xdc434) is rare — kept
tier1 — behavioral string "Unable to seek to position" (fn 0xd434f) is rare — kept
tier1 — behavioral string "VDbAYZkdIB" (fn 0xdc434) is rare — kept
tier1 — behavioral string "Wrong secret key format. A hex string of 64 chars is expected" (fn 0xd434f) is rare — kept
tier1 — behavioral string "akiranew" (fn 0xd434f) is rare — kept
tier1 — behavioral string "akiranew.txt" (fn 0xd434f) is rare — kept
tier1 — behavioral string "assertion failed: input.len() == output.len()" (fn 0xd434f) is rare — kept
tier1 — candidate behavioral string "called `Result::unwrap()` on an `Err` value" appears in the benign corpus, dropping it (not rare)
tier1 — candidate behavioral string "cpu.cfs_period_us" appears in the benign corpus, dropping it (not rare)
tier1 — candidate behavioral string "cpu.cfs_quota_us" appears in the benign corpus, dropping it (not rare)
tier1 — candidate behavioral string "exclude" appears in the benign corpus, dropping it (not rare)
tier1 — candidate behavioral string "failed to spawn thread" appears in the benign corpus, dropping it (not rare)
tier1 — behavioral string "note write fail" (fn 0xd38a5) is rare — kept
tier1 — behavioral string "stopvm" (fn 0xdc434) is rare — kept
tier1 — candidate behavioral string "threads" appears in the benign corpus, dropping it (not rare)
tier1 — behavioral string "vmonly" (fn 0xdc434) is rare — kept
tier1 — behavioral string "{prefix:.bold.dim} {spinner} {wide_msg}" (fn 0xdc434) is rare — kept
tier1 — behavioral string "{prefix:.bold.dim} {spinner} {wide_msg} {bytes_per_sec}" (fn 0xd38a5) is rare — kept
tier1 — behavioral string "{spinner:.green} [{elapsed_precise}] {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})" (fn 0xd434f) is rare — kept
tier1 — masked atom for fn 0xd25af shares its function with a kept behavioral string; dropped from the code factor to keep the two factors independent (architecture §6)
tier1 — masked atom for fn 0xd38a5 shares its function with a kept behavioral string; dropped from the code factor to keep the two factors independent (architecture §6)
tier1 — masked atom for fn 0xd434f shares its function with a kept behavioral string; dropped from the code factor to keep the two factors independent (architecture §6)
tier1 — masked atom for fn 0xdc434 shares its function with a kept behavioral string; dropped from the code factor to keep the two factors independent (architecture §6)
tier1 — independence partition: code factor from 3 function(s) {0xc805c, 0xc8116, 0xc94ea}, string factor from 4 function(s) {0xd25af, 0xd38a5, 0xd434f, 0xdc434} (disjoint)
wrote /home/user/Videos/winnow/rules/akira_v2_x_tier1.yar (TIER 1 EARNED — 3 masked-code atoms, 23 independent behavioral strings)
```

## blackcat_sphynx_x
```
wrote /home/user/Videos/winnow/rules/blackcat_sphynx_x.yar (1 STRONG fns, 1 panic strings, 3 code atoms)
tier1 — measuring against benign corpus (39 files)
tier1 — masked atom for fn 0x4cd90 reduced 1124B → 64B window at +0x1b (64 exact bytes, 0 corpus collisions)
tier1 — code factor: 1 atom(s) reduced & kept, 0 dropped as non-discriminative
tier1 — behavioral string "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list" (fn 0x4cd90) is rare — kept
tier1 — masked atom for fn 0x4cd90 shares its function with a kept behavioral string; dropped from the code factor to keep the two factors independent (architecture §6)
TIER 1 NOT EARNED for c0e70e69d8f7432383fa37528cd42db764b73dd08eb75d72229c2a0d02e538cc — the code and behavioral factors are not independent: every function with a discriminative masked atom also produced the kept behavioral string(s), so no disjoint (code fn ≠ string fn) pairing exists (architecture §6). This is the single-STRONG-function case — one function cannot corroborate itself. Tier 1 is the fortunate case (architecture §5); Tier 2 rule above still stands.
```

## 01flip_x
```
TIER 0 REFUSE — no STRONG-tier author functions in /home/user/malware-samples/01flip_x/e5834b7bdd70ec904470d541713e38fe933e96a4e49f80dbfb25148d9674f957.elf
        (packed binary, aggressive path remapping, or no reachable user panic evidence)
```

## p2pinfect_x
```
TIER 0 REFUSE — no STRONG-tier author functions in /home/user/malware-samples/p2pinfect_x/3a43116d507d58f3c9717f2cb0a3d06d0c5a7dc29f601e9c2b976ee6d9c8713f.elf
        (packed binary, aggressive path remapping, or no reachable user panic evidence)
```

