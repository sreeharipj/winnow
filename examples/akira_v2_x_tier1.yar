rule winnow_tier1_0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c {
  meta:
    generator = "winnow-phase3"
    tier = "1"
    sample = "0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c"
    sample_path = "/home/user/malware-samples/akira_v2_x/0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c.elf"
    sample_sha256 = "0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c"
    min_anchors = 2
    strong_functions = 7
    confirming_panic_strings = "akiranew/src/lock.rs; akiranew/src/main.rs; akiranew/src/path_finder.rs; akiranew/src/prng.rs"
    benign_corpus_size = 78
    independence = "structural: code factor from function(s) {0xc805c, 0xc8116, 0xc94ea}; string factor from function(s) {0xd25af, 0xd38a5, 0xd434f, 0xdc434}. The two function sets are disjoint, so any match of `any of ($mcode*) and any of ($behavior*)` necessarily pairs a masked code atom and a behavioral string from DIFFERENT functions — the §6 independence the FP argument multiplies over is enforced by construction, not asserted."
    rests_on = "masked-hex code factor (relocation-patched operands, RIP-relative displacements, and 64-bit absolute immediates masked; substring-reduced against the benign corpus, architecture critique finding 2) AND an independent non-panic author-data string (rarity-filtered against the same corpus), drawn from a disjoint set of functions (see independence). Panic-path strings are confirming only (architecture section 6) and are listed above in meta, not required by this rule's condition, so they are never double-counted as independent evidence."
  strings:
    $mcode0 = { 4C 39 E9 74 73 48 8D 59 18 49 89 1E 48 8B 39 48 8B 71 10 E8 51 07 10 00 48 89 C7 48 89 D6 4C 89 FA E8 4A 42 00 00 48 89 C7 48 89 D6 E8 B2 16 00 00 48 89 C7 48 89 D6 4C 89 E2 E8 31 42 00 00 48 } // fn 0xc805c
    $mcode1 = { 4C 39 E9 74 73 48 8D 59 18 49 89 1E 48 8B 39 48 8B 71 10 E8 97 06 10 00 48 89 C7 48 89 D6 4C 89 FA E8 90 41 00 00 48 89 C7 48 89 D6 E8 F8 15 00 00 48 89 C7 48 89 D6 4C 89 E2 E8 77 41 00 00 48 } // fn 0xc8116
    $mcode2 = { 4C 89 F7 E8 11 2F 00 00 49 89 C7 88 54 24 07 89 E8 83 E0 1F 45 0F B6 64 07 08 4D 89 FD 49 83 C5 08 41 81 CC 00 04 00 00 66 41 83 EC 01 72 25 41 88 6F 40 4C 89 F7 4C 89 EE E8 3C 1E 01 00 0F 10 } // fn 0xc94ea
    $behavior0 = "/akiranew.txt" ascii // fn 0xd38a5
    $behavior1 = "/altbootbank" ascii // fn 0xd25af
    $behavior2 = "/locker" ascii // fn 0xd25af
    $behavior3 = "/lost+found" ascii // fn 0xd25af
    $behavior4 = "/productLocker" ascii // fn 0xd25af
    $behavior5 = "/tmp/stop_vms.sh" ascii // fn 0xdc434
    $behavior6 = "/vmfs/devices" ascii // fn 0xd25af
    $behavior7 = "/vmfs/volumes" ascii // fn 0xd25af
    $behavior8 = "/vmimages/" ascii // fn 0xd25af
    $behavior9 = "/vmupgrade" ascii // fn 0xd25af
    $behavior10 = "TODO: panic message" ascii // fn 0xdc434
    $behavior11 = "Unable to seek to position" ascii // fn 0xd434f
    $behavior12 = "VDbAYZkdIB" ascii // fn 0xdc434
    $behavior13 = "Wrong secret key format. A hex string of 64 chars is expected" ascii // fn 0xd434f
    $behavior14 = "akiranew" ascii // fn 0xd434f
    $behavior15 = "akiranew.txt" ascii // fn 0xd434f
    $behavior16 = "assertion failed: input.len() == output.len()" ascii // fn 0xd434f
    $behavior17 = "note write fail" ascii // fn 0xd38a5
    $behavior18 = "stopvm" ascii // fn 0xdc434
    $behavior19 = "vmonly" ascii // fn 0xdc434
    $behavior20 = "{prefix:.bold.dim} {spinner} {wide_msg} {bytes_per_sec}" ascii // fn 0xd38a5
    $behavior21 = "{spinner:.green} [{elapsed_precise}] {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})" ascii // fn 0xd434f
  condition:
    uint32(0) == 0x464c457f and any of ($mcode*) and any of ($behavior*)
}
