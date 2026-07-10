#!/usr/bin/env bash
# Phase 0 — benign corpus builder.
#
# CRITICAL: every entry here is git-cloned and `cargo build --release`d from
# source. Do NOT switch this to `cargo install <crate>` — cargo install builds
# from ~/.cargo/registry/, so the tool's own `src/*.rs` paths get rewritten to
# `registry/...` and unhusk classifies the author's code as Dep, not User.
# That silently defeats the entire point of this corpus: it must exercise the
# same User-attribution path the malware rules rest on, or the benign FP
# measurement is meaningless.
#
# Usage: scripts/build_corpus.sh [batch_start] [batch_end]
#   With no args, builds the whole list. With two indices (0-based, exclusive
#   end), builds only that slice — used to keep individual invocations under
#   the tool timeout.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/corpus/_build"
BIN="$ROOT/corpus/bin"
MANIFEST="$ROOT/corpus/manifest.csv"
FAILLOG="$ROOT/corpus/build_failures.log"
UNHUSK="/home/user/Videos/unhusk/target/release/unhusk"

# Tunables (defaults preserve the original behaviour). Overridable via env for
# unattended runs on RAM-constrained hosts: PBUILD=1 avoids concurrent heavy
# links (the OOM cause), JOBS controls per-crate cargo parallelism, and
# BUILD_TIMEOUT hard-caps a single crate so one wedged build can't stall a batch.
PBUILD="${PBUILD:-2}"
JOBS="${JOBS:-4}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-86400}"

mkdir -p "$WORK" "$BIN"

# name;git_url;bin_name;category
# category in {cli,async,parallel}
ENTRIES=(
  "ripgrep;https://github.com/BurntSushi/ripgrep;rg;parallel"
  "fd;https://github.com/sharkdp/fd;fd;parallel"
  "bat;https://github.com/sharkdp/bat;bat;cli"
  "tokei;https://github.com/XAMPPRocky/tokei;tokei;parallel"
  "hyperfine;https://github.com/sharkdp/hyperfine;hyperfine;cli"
  "sd;https://github.com/chmln/sd;sd;cli"
  "dust;https://github.com/bootandy/dust;dust;parallel"
  "procs;https://github.com/dalance/procs;procs;cli"
  "bottom;https://github.com/ClementTsang/bottom;btm;cli"
  "zoxide;https://github.com/ajeetdsouza/zoxide;zoxide;cli"
  "hexyl;https://github.com/sharkdp/hexyl;hexyl;cli"
  "grex;https://github.com/pemistahl/grex;grex;cli"
  "choose;https://github.com/theryangeary/choose;choose;cli"
  "tealdeer;https://github.com/dbrgn/tealdeer;tldr;async"
  "just;https://github.com/casey/just;just;cli"
  "broot;https://github.com/Canop/broot;broot;cli"
  "delta;https://github.com/dandavison/delta;delta;cli"
  "eza;https://github.com/eza-community/eza;eza;cli"
  "xh;https://github.com/ducaale/xh;xh;async"
  "oha;https://github.com/hatoo/oha;oha;async"
  "gping;https://github.com/orf/gping;gping;async"
  "miniserve;https://github.com/svenstaro/miniserve;miniserve;async"
  "dog;https://github.com/ogham/dog;dog;async"
  "watchexec;https://github.com/watchexec/watchexec;watchexec;async"
  "difftastic;https://github.com/Wilfred/difftastic;difft;parallel"
  "bacon;https://github.com/Canop/bacon;bacon;cli"
  "starship;https://github.com/starship/starship;starship;async"
  "fend;https://github.com/printfn/fend;fend;cli"
  "mdbook;https://github.com/rust-lang/mdBook;mdbook;cli"
  "mdcat;https://github.com/swsnr/mdcat;mdcat;cli"
  "jaq;https://github.com/01mf02/jaq;jaq;cli"
  "viu;https://github.com/atanunq/viu;viu;cli"
  "websocat;https://github.com/vi/websocat;websocat;async"
  "rathole;https://github.com/rapiz1/rathole;rathole;async"
  "dua-cli;https://github.com/Byron/dua-cli;dua;parallel"
  "fclones;https://github.com/pkolaczk/fclones;fclones;parallel"
  "rage;https://github.com/str4d/rage;rage;cli"
  "xplr;https://github.com/sayanarijit/xplr;xplr;cli"
  "navi;https://github.com/denisidoro/navi;navi;cli"
  "csvlens;https://github.com/YS-L/csvlens;csvlens;cli"
  "rare;https://github.com/zix99/rare;rare;parallel"
  "rip;https://github.com/MilesCranmer/rip;rip;cli"
  "bore;https://github.com/ekzhang/bore;bore;async"
  "hurl;https://github.com/Orange-OpenSource/hurl;hurl;async"
  "silicon;https://github.com/Aloxaf/silicon;silicon;cli"
  "gitui-lite-skip;SKIP;skip;skip"
  "diskonaut;https://github.com/imsnif/diskonaut;diskonaut;parallel"
  "ripgrep-all;https://github.com/phiresky/ripgrep-all;rga;parallel"
  "tickrs;https://github.com/tarkah/tickrs;tickrs;async"
  "so;https://github.com/samtay/so;so;async"
  "presenterm;https://github.com/mfontanini/presenterm;presenterm;cli"
  "runiq;https://github.com/chuckyblack/runiq;runiq;cli"
  "rustscan;https://github.com/RustScan/RustScan;rustscan;async"
  "feroxbuster;https://github.com/epi052/feroxbuster;feroxbuster;async"
  "lsd;https://github.com/lsd-rs/lsd;lsd;cli"
  "tre-command;https://github.com/dduan/tre;tre;cli"
  "pastel;https://github.com/sharkdp/pastel;pastel;cli"
  "git-cliff;https://github.com/orhun/git-cliff;git-cliff;cli"
  "typos;https://github.com/crate-ci/typos;typos;cli"
  "rust-parallel;https://github.com/aaronriekenberg/rust-parallel;rust-parallel;async"
  "xcp;https://github.com/tarka/xcp;xcp;parallel"
  "monolith;https://github.com/Y2Z/monolith;monolith;async"
  "rustypaste;https://github.com/orhun/rustypaste;rustypaste;async"
  "topgrade;https://github.com/topgrade-rs/topgrade;topgrade;cli"
  "zellij;https://github.com/zellij-org/zellij;zellij;async"
  "ouch;https://github.com/ouch-org/ouch;ouch;parallel"
  "diffr;https://github.com/mookid/diffr;diffr;cli"
  "ov;https://github.com/noborus/ov;ov;cli"
  "systeroid;https://github.com/systeroid/systeroid;systeroid;cli"
  "rust-code-analysis;https://github.com/mozilla/rust-code-analysis;rust-code-analysis-cli;parallel"
  "hexpatch;https://github.com/Etto48/HexPatch;hexpatch;cli"
  "bandwhich2-skip;SKIP;skip;skip"
  "gpg-tui;https://github.com/orhun/gpg-tui;gpg-tui;cli"
  "kondo;https://github.com/tbillington/kondo;kondo;parallel"
  "hyperjson-skip;SKIP;skip;skip"
  "wthrr;https://github.com/TheJokr/wthrr-the-weathercli;wthrr;async"
  "trippy;https://github.com/fujiapple852/trippy;trip;async"
  # --- grow batch 2026-07-10 (indices >= 77): more real Rust CLIs to enlarge the
  # held-out FP corpus B. Biased to well-known, mostly-pure-Rust tools with known
  # binary names; failures are non-fatal (continue-on-fail) and just don't land. ---
  "vivid;https://github.com/sharkdp/vivid;vivid;cli"
  "numbat;https://github.com/sharkdp/numbat;numbat;cli"
  "diskus;https://github.com/sharkdp/diskus;diskus;parallel"
  "jless;https://github.com/PaulJuliusMartinez/jless;jless;cli"
  "htmlq;https://github.com/mgdm/htmlq;htmlq;cli"
  "xsv;https://github.com/BurntSushi/xsv;xsv;parallel"
  "b3sum;https://github.com/BLAKE3-team/BLAKE3;b3sum;parallel"
  "sad;https://github.com/ms-jpq/sad;sad;cli"
  "kibi;https://github.com/ilai-deutel/kibi;kibi;cli"
  "rink;https://github.com/tiffany352/rink-rs;rink;cli"
  "genact;https://github.com/svenstaro/genact;genact;cli"
  "mprocs;https://github.com/pvolok/mprocs;mprocs;cli"
  "onefetch;https://github.com/o2sh/onefetch;onefetch;parallel"
  "hgrep;https://github.com/rhysd/hgrep;hgrep;cli"
  "taplo;https://github.com/tamasfe/taplo;taplo;cli"
  "stylua;https://github.com/JohnnyMorganz/StyLua;stylua;cli"
  "dprint;https://github.com/dprint/dprint;dprint;parallel"
  "serie;https://github.com/lusingander/serie;serie;cli"
  "joshuto;https://github.com/kamiyaa/joshuto;joshuto;cli"
  "gitui;https://github.com/extrawurst/gitui;gitui;cli"
  "skim;https://github.com/skim-rs/skim;sk;cli"
  "television;https://github.com/alexpasmantier/television;tv;cli"
  "cotp;https://github.com/replydev/cotp;cotp;cli"
  "fnm;https://github.com/Schniz/fnm;fnm;async"
  "mise;https://github.com/jdx/mise;mise;cli"
  "atuin;https://github.com/atuinsh/atuin;atuin;async"
  "pueue;https://github.com/Nukesor/pueue;pueue;async"
  "slumber;https://github.com/LucasPickering/slumber;slumber;async"
  "gitoxide;https://github.com/GitoxideLabs/gitoxide;gix;parallel"
  "ruff;https://github.com/astral-sh/ruff;ruff;parallel"
  "uv;https://github.com/astral-sh/uv;uv;async"
  "helix;https://github.com/helix-editor/helix;hx;cli"
  "rustic;https://github.com/rustic-rs/rustic;rustic;async"
  "kalker;https://github.com/PaddiM8/kalker;kalker;cli"
  "oxipng;https://github.com/shssoichiro/oxipng;oxipng;parallel"
  "git-graph;https://github.com/mlange-42/git-graph;git-graph;cli"
  "macchina;https://github.com/Macchina-CLI/macchina;macchina;cli"
  "lolcrab;https://github.com/mazznoer/lolcrab;lolcrab;cli"
  "zet;https://github.com/yarrow/zet;zet;cli"
  "bkt;https://github.com/dimo414/bkt;bkt;cli"
  "committed;https://github.com/crate-ci/committed;committed;cli"
  "ripsecrets;https://github.com/sirwart/ripsecrets;ripsecrets;cli"
  "static-web-server;https://github.com/static-web-server/static-web-server;static-web-server;async"
  "code2prompt;https://github.com/mufeedvh/code2prompt;code2prompt;cli"
  "eva;https://github.com/nerdypepper/eva;eva;cli"
  "sccache;https://github.com/mozilla/sccache;sccache;parallel"
  "amp;https://github.com/jmacdonald/amp;amp;cli"
  "yazi;https://github.com/sxyazi/yazi;yazi;async"
  "mdq;https://github.com/yshavit/mdq;mdq;cli"
  "nushell;https://github.com/nushell/nushell;nu;cli"
  # --- grow batch 3 2026-07-10 (indices >= 127): deeper into the tail; more
  # failures expected, still net corpus growth. ---
  "tuc;https://github.com/riquito/tuc;tuc;cli"
  "hck;https://github.com/sstadick/hck;hck;cli"
  "dtool;https://github.com/guoxbin/dtool;dtool;cli"
  "fastmod;https://github.com/facebookincubator/fastmod;fastmod;cli"
  "amber;https://github.com/dalance/amber;ambr;cli"
  "repgrep;https://github.com/acheronfail/repgrep;rgr;cli"
  "ruplacer;https://github.com/your-tools/ruplacer;ruplacer;parallel"
  "counts;https://github.com/nnethercote/counts;counts;cli"
  "httm;https://github.com/kimono-koans/httm;httm;parallel"
  "fw;https://github.com/brocode/fw;fw;cli"
  "jql;https://github.com/yamafaktory/jql;jql;cli"
  "jnv;https://github.com/ynqa/jnv;jnv;cli"
  "rmesg;https://github.com/polyverse/rmesg;rmesg;cli"
  "wiki-tui;https://github.com/Builditluc/wiki-tui;wiki-tui;async"
  "rainfrog;https://github.com/achristmascarl/rainfrog;rainfrog;async"
  "atac;https://github.com/Julien-cpsn/ATAC;atac;async"
  "huniq;https://github.com/koraa/huniq;huniq;cli"
  "taskwarrior-tui;https://github.com/kdheepak/taskwarrior-tui;taskwarrior-tui;cli"
  "oxker;https://github.com/mrjackwills/oxker;oxker;async"
  "systemctl-tui;https://github.com/rgwood/systemctl-tui;systemctl-tui;cli"
  "serpl;https://github.com/yassinebridi/serpl;serpl;cli"
  "scooter;https://github.com/thomasschafer/scooter;scooter;cli"
  "gitu;https://github.com/altsem/gitu;gitu;cli"
  "pik;https://github.com/jacek-kurlit/pik;pik;cli"
  "toipe;https://github.com/Samyak2/toipe;toipe;cli"
  "russ;https://github.com/ckampfe/russ;russ;async"
  "otree;https://github.com/fioncat/otree;otree;cli"
  "rnr;https://github.com/ismaelgv/rnr;rnr;cli"
  "diffsitter;https://github.com/afnanenayet/diffsitter;diffsitter;cli"
  "kmon;https://github.com/orhun/kmon;kmon;cli"
  "hwatch;https://github.com/blacknon/hwatch;hwatch;cli"
  "pipes-rs;https://github.com/lhvy/pipes-rs;pipes-rs;cli"
)

start="${1:-0}"
end="${2:-${#ENTRIES[@]}}"

: > "$FAILLOG.$start-$end"

echo "name,git_url,commit_sha,bin_name,category,eh_frame_removed,strong_functions" \
  > "$MANIFEST.$start-$end"

build_one() {
  local entry="$1"
  IFS=';' read -r name url binname category <<< "$entry"
  [[ "$url" == "SKIP" ]] && return 0

  # Resumable: if this binary was already built (e.g. by an earlier interrupted
  # run), re-record its manifest row and skip the rebuild, so the batch is cheap
  # to resume after an interruption instead of recompiling everything. Bins are
  # only copied out after a fully successful build, so an existing one is complete.
  if [[ -f "$BIN/$name" ]]; then
    local rsha rstrong="?"
    rsha="$(git -C "$WORK/$name" rev-parse --short HEAD 2>/dev/null || echo cached)"
    if [[ -x "$UNHUSK" ]]; then
      rstrong="$("$UNHUSK" "$BIN/$name" --precision --json 2>/dev/null | grep -o '"tier"' | wc -l | tr -d ' ')"
    fi
    echo "$name,$url,$rsha,$binname,$category,false,$rstrong" >> "$MANIFEST.$start-$end"
    echo "SKIP(exists): $name"
    return 0
  fi

  # Disk-space guard: this host runs near-full from unrelated data. Bail
  # before starting a multi-hundred-MB build if headroom is too thin.
  local avail_kb
  avail_kb="$(df -Pk "$WORK" | awk 'NR==2{print $4}')"
  if [[ "$avail_kb" -lt 2097152 ]]; then
    echo "$name: SKIPPED (low disk: ${avail_kb}KB free)" >> "$FAILLOG.$start-$end"
    return 1
  fi

  local dir="$WORK/$name"
  if [[ ! -d "$dir/.git" ]]; then
    rm -rf "$dir"
    local cloned=1
    for attempt in 1 2 3; do
      if git clone --depth 1 -q "$url" "$dir" 2>>"$FAILLOG.$start-$end"; then
        cloned=0
        break
      fi
      rm -rf "$dir"
      sleep $((attempt * 4))
    done
    if [[ "$cloned" != "0" ]]; then
      echo "$name: CLONE FAILED" >> "$FAILLOG.$start-$end"
      return 1
    fi
  fi

  local sha
  sha="$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"

  # Some repos are workspaces; try building at root first, then search for
  # the binary anywhere under target/release.
  if ! (cd "$dir" && timeout -k 30 "$BUILD_TIMEOUT" cargo build --release --locked -j"$JOBS" >/dev/null 2>>"$FAILLOG.$start-$end"); then
    if ! (cd "$dir" && timeout -k 30 "$BUILD_TIMEOUT" cargo build --release -j"$JOBS" >/dev/null 2>>"$FAILLOG.$start-$end"); then
      echo "$name: BUILD FAILED" >> "$FAILLOG.$start-$end"
      rm -rf "$dir/target"
      return 1
    fi
  fi

  local built
  built="$(find "$dir" -type f -path "*/release/$binname" -perm -u+x 2>/dev/null | head -1)"
  if [[ -z "$built" ]]; then
    echo "$name: BINARY NOT FOUND ($binname)" >> "$FAILLOG.$start-$end"
    rm -rf "$dir/target"
    return 1
  fi

  local out="$BIN/$name"
  cp "$built" "$out"
  strip "$out" 2>>"$FAILLOG.$start-$end"

  # Disk is tight on this host (near-full from unrelated data) — a `target/`
  # dir can be 200MB-900MB and there is no headroom to leave ~50 of them on
  # disk at once. The binary is already copied out; reclaim immediately.
  rm -rf "$dir/target"

  local strong="?"
  if [[ -x "$UNHUSK" ]]; then
    strong="$("$UNHUSK" "$out" --precision --json 2>/dev/null | \
      grep -o '"tier"' | wc -l | tr -d ' ')"
  fi

  echo "$name,$url,$sha,$binname,$category,false,$strong" >> "$MANIFEST.$start-$end"

  # eh_frame-removed variant for a diagnostic subset (every 6th entry).
  local idx_mod=$(( $(echo "$name" | cksum | cut -d' ' -f1) % 6 ))
  if [[ "$idx_mod" == "0" ]]; then
    local out_noeh="$BIN/${name}_noeh"
    cp "$out" "$out_noeh"
    objcopy --remove-section .eh_frame "$out_noeh" 2>>"$FAILLOG.$start-$end"
    local strong_noeh="?"
    if [[ -x "$UNHUSK" ]]; then
      strong_noeh="$("$UNHUSK" "$out_noeh" --precision --json 2>/dev/null | \
        grep -o '"tier"' | wc -l | tr -d ' ')"
    fi
    echo "${name}_noeh,$url,$sha,$binname,$category,true,$strong_noeh" >> "$MANIFEST.$start-$end"
  fi

  echo "OK: $name (strong=$strong)"
}
export -f build_one
export WORK BIN MANIFEST FAILLOG UNHUSK start end JOBS BUILD_TIMEOUT

printf '%s\n' "${ENTRIES[@]:$start:$((end-start))}" | \
  xargs -I{} -P "$PBUILD" bash -c 'build_one "$@"' _ {}

echo "Batch $start-$end done. See $MANIFEST.$start-$end and $FAILLOG.$start-$end"
