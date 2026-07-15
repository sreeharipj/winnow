# winnow.tape — regenerate docs/winnow.gif deterministically with:  vhs winnow.tape
#
# Prereqs (one-time, see the README / demo/ notes):
#   - `winnow` and `unhusk` on PATH   (cargo build --release in each repo, then
#     symlink into ./.bin and run vhs with PATH="$PWD/.bin:$PATH")
#   - a *stripped* sample at ./demo/akira_v2_x
#   - the benign filter corpus at ./corpus/split_a   (scripts/build_corpus.sh
#     then scripts/split_corpus.sh) — the documented filter half A (78 files)
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
Sleep 400ms

# beat 1 — the premise in one line: this is a stripped binary. Symbols are gone.
Type "file akira_v2_x"
Sleep 300ms
Enter
Sleep 1300ms

# beat 2 — one command. winnow shells out to unhusk to recover the author's
# functions from panic metadata, then measures every candidate atom and string
# against the benign filter corpus before it keeps anything.
Type "winnow akira_v2_x --tier1 --corpus-dir ../corpus/split_a"
Sleep 300ms
Enter
Sleep 2s

# beat 3 — the payoff: a real, complete Tier 1 YARA-X rule. Its condition ANDs
# two independent factors — a masked code atom and a behavioral string — drawn
# from disjoint functions.
Type "cat akira_v2_x_tier1.yar"
Sleep 300ms
Enter
Sleep 2200ms

# beat 4 — zoom in on the code factor. The call/jmp targets that shift across
# recompiles are wildcarded (?? ?? ?? ??); the author's instruction skeleton
# stays exact. That is what lets one atom survive a rebuild without going
# generic enough to match the neighbourhood.
Type "grep -E 'mcode[0-9]' akira_v2_x_tier1.yar"
Sleep 300ms
Enter
Sleep 3200ms
