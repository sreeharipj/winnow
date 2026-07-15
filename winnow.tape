# winnow.tape — regenerate docs/winnow.gif deterministically with:  vhs winnow.tape
#
# Prereqs (one-time, see winnow.tape prep in the README / demo/ below):
#   - `winnow` and `unhusk` on PATH   (cargo build --release in each repo, then symlink/PATH)
#   - a *stripped* sample at ./demo/akira_v2_x
#   - the benign corpus at ./corpus/bin   (scripts/build_corpus.sh)
# Run from the repo root.

Output docs/winnow.gif

Require winnow
Require unhusk

Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Padding 24

# --- off-camera: drop into the (gitignored) demo dir with a clean screen ---
Hide
Type "cd demo && clear"
Enter
Show
Sleep 500ms

# beat 1 — the premise in one line: this is a stripped binary. Symbols are gone.
Type "file akira_v2_x"
Sleep 300ms
Enter
Sleep 2s

# beat 2 — one command. winnow shells out to unhusk to recover the author's
# functions from panic metadata, then measures every candidate atom and string
# against the benign corpus before it keeps anything.
Type "winnow akira_v2_x --tier1 --corpus-dir ../corpus/bin"
Sleep 300ms
Enter
Sleep 5s

# beat 3 — the payoff: a real Tier 1 YARA-X rule falls out. The condition ANDs
# two independent factors — a masked code atom and a behavioral string, drawn
# from disjoint functions.
Type "cat akira_v2_x_tier1.yar"
Sleep 300ms
Enter
Sleep 6s
