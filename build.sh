#!/usr/bin/env sh
# Cross-build the x64 loader lab with MinGW-w64 (Linux/WSL or Git Bash).
# The binaries are lab artifacts only; nothing is executed by this script.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CC=${CC:-x86_64-w64-mingw32-gcc}
OUT=${OUT:-"$ROOT/dist"}
SEED=${SEED:-0x13579bdf}
ALT_SEED=${ALT_SEED:-0xdeadbeef}
FLAGS="-std=c11 -O2 -g -Wall -Wextra -Werror -D_WIN32_WINNT=0x0601 -D__USE_MINGW_ANSI_STDIO=1 -static-libgcc"

mkdir -p "$OUT"
: > "$OUT/build.log"
{
  printf 'UTC: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'Compiler: %s\n' "$CC"
  printf 'Seed: %s  alt: %s\n' "$SEED" "$ALT_SEED"
  "$CC" --version | head -1
} >> "$OUT/build.log"

python3 "$ROOT/tools/gen_api_hashes.py" --seed "$SEED" \
  --out "$ROOT/src/api_hashes.h" >> "$OUT/build.log"
python3 "$ROOT/tools/gen_api_hashes.py" --seed "$ALT_SEED" \
  --out "$OUT/api_hashes_alt.h" >> "$OUT/build.log"

common_sources="$ROOT/src/hash.c $ROOT/src/resolver.c $ROOT/src/ntapi.c $ROOT/src/log.c"

compile() {
  output=$1
  shift
  if ! "$CC" $FLAGS "$@" -o "$output" >> "$OUT/build.log" 2>&1; then
    echo "Build failed: $output" >&2
    tail -50 "$OUT/build.log" >&2
    exit 1
  fi
  printf 'Built %s\n' "$(basename "$output")" | tee -a "$OUT/build.log"
}

compile "$OUT/footless_loader.exe" -DFOOTLESS_DEFAULT_SEED_VALUE="$SEED" $common_sources "$ROOT/src/inject.c" "$ROOT/src/main.c"
compile "$OUT/footless_loader_seeded.exe" -DFOOTLESS_DEFAULT_VARIANT=1 \
  -DFOOTLESS_DEFAULT_SEED_VALUE="$SEED" $common_sources "$ROOT/src/inject.c" "$ROOT/src/main.c"
compile "$OUT/footless_loader_module_api.exe" -DFOOTLESS_DEFAULT_VARIANT=2 \
  -DFOOTLESS_DEFAULT_SEED_VALUE="$SEED" $common_sources "$ROOT/src/inject.c" "$ROOT/src/main.c"
compile "$OUT/footless_loader_quiet.exe" -DFOOTLESS_QUIET \
  -DFOOTLESS_DEFAULT_SEED_VALUE="$SEED" $common_sources "$ROOT/src/inject.c" "$ROOT/src/main.c"
compile "$OUT/footless_loader_seed_alt.exe" -include "$OUT/api_hashes_alt.h" \
  -DFOOTLESS_DEFAULT_SEED_VALUE="$ALT_SEED" \
  $common_sources "$ROOT/src/inject.c" "$ROOT/src/main.c"
compile "$OUT/footless_target.exe" "$ROOT/src/target.c" "$ROOT/src/log.c"
compile "$OUT/benign_app.exe" "$ROOT/src/benign.c"
compile "$OUT/footless_marker.dll" -shared "$ROOT/src/marker.c" "$ROOT/src/log.c"

(
  cd "$OUT"
  sha256sum footless_loader.exe footless_loader_seeded.exe \
    footless_loader_module_api.exe footless_loader_quiet.exe \
    footless_loader_seed_alt.exe footless_target.exe benign_app.exe \
    footless_marker.dll > sha256.txt
)

printf 'Build completed. No binary was executed.\n'
