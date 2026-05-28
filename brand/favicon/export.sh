#!/usr/bin/env bash
# Batch export PNGs from favicon.svg
# Requires one of: inkscape, rsvg-convert, or svgexport

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/favicon.svg"
OUT="$SCRIPT_DIR"

sizes=(
  "favicon-16:16"
  "favicon-32:32"
  "apple-touch-icon:180"
  "android-chrome-192:192"
  "android-chrome-512:512"
  "og-logo:512"
)

export_png() {
  local name="$1" size="$2" dest="$OUT/$name.png"

  if command -v inkscape &>/dev/null; then
    inkscape "$SRC" --export-type=png --export-filename="$dest" \
      --export-width="$size" --export-height="$size"
  elif command -v rsvg-convert &>/dev/null; then
    rsvg-convert -w "$size" -h "$size" "$SRC" -o "$dest"
  elif command -v svgexport &>/dev/null; then
    svgexport "$SRC" "$dest" "${size}:${size}"
  else
    echo "ERROR: Install inkscape, rsvg-convert (librsvg), or svgexport (npm i -g svgexport)" >&2
    exit 1
  fi

  echo "Exported $dest (${size}x${size})"
}

for entry in "${sizes[@]}"; do
  name="${entry%%:*}"
  size="${entry##*:}"
  export_png "$name" "$size"
done

echo "Done. PNGs are in: $OUT"
