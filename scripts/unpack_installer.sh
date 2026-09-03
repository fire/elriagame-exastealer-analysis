#!/usr/bin/env bash
# unpack_installer.sh — end-to-end static unpack of an "ElriaGame"-style
# Exastealer installer on macOS or Linux. Never executes the sample.
#
#   unpack_installer.sh <ElriaGame.exe> [out_dir]
#
# Requirements: sevenzip (`brew install sevenzip` or `apt install 7zip`),
# node, npx (for @electron/asar), and js-beautify (optional, via npx).

set -euo pipefail

INPUT="${1:-}"
OUT="${2:-./out}"

if [[ -z "$INPUT" ]]; then
  echo "usage: $0 <ElriaGame.exe> [out_dir]" >&2
  exit 2
fi
if [[ ! -f "$INPUT" ]]; then
  echo "not a file: $INPUT" >&2
  exit 2
fi

# Verify tooling
for cmd in 7zz node npx shasum file; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing: $cmd" >&2; exit 2; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"

echo "== hash =="
shasum -a 256 "$INPUT"

echo "== 1. unpack NSIS SFX =="
7zz x -y -o"$OUT/nsis" "$INPUT" >/dev/null
ls "$OUT/nsis/\$PLUGINSDIR/"

echo "== 2. unpack app-64.7z =="
7zz x -y -o"$OUT/app" "$OUT/nsis/\$PLUGINSDIR/app-64.7z" >/dev/null

echo "== 3. extract app.asar =="
npx --yes @electron/asar extract "$OUT/app/resources/app.asar" "$OUT/asar-out" >/dev/null

echo "== 4. peel launcher1.js =="
node "$HERE/peel_launcher.js" "$OUT/asar-out/launcher1.js" "$OUT"
if command -v npx >/dev/null 2>&1; then
  npx --yes js-beautify "$OUT/final.js" -o "$OUT/final.pretty.js" >/dev/null 2>&1 || true
fi

echo "== 5. recover archive password from stage-4 =="
PWD_LINE="$(grep -E 'ARCHIVE_PASSWORD' "$OUT/final.js" | head -1 || true)"
if [[ -z "$PWD_LINE" ]]; then
  echo "could not find ARCHIVE_PASSWORD in stage-4; sample may differ from the analyzed build." >&2
  exit 1
fi
PASSWORD="$(echo "$PWD_LINE" | sed -E 's/.*"([^"]+)".*/\1/' | head -1)"
echo "  password = $PASSWORD"

echo "== 6. unpack data.7z =="
7zz x -y -p"$PASSWORD" -o"$OUT/data" "$OUT/app/resources/data.7z" >/dev/null
ls "$OUT/data"

echo "== 7. explode the JAR =="
mkdir -p "$OUT/jar"
( cd "$OUT/jar" && 7zz x -y "$OUT/data/emre.jar" >/dev/null ) || true

echo
echo "done. see:"
echo "  $OUT/final.pretty.js      # deobfuscated dropper"
echo "  $OUT/data/emre.jar        # Exastealer payload (do not run)"
echo "  $OUT/jar/                 # exploded JAR"
echo
echo "the JAR is live malware. do not decompile it on a machine you care about,"
echo "and do not add it to git — .gitignore in this repo already blocks it."
