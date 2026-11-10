#!/usr/bin/env bash
# Assemble the GitHub Pages site into _site/, reusing the portal's fonts and
# hero image and the README screenshots so there is one copy of each asset.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/_site}
rm -rf "$OUT"
mkdir -p "$OUT/assets/fonts" "$OUT/assets/screenshots"
cp "$ROOT/site/index.html" "$ROOT/site/site.css" "$OUT/"
cp "$ROOT/site/favicon.svg" "$OUT/assets/"
cp "$ROOT"/internal/portal/static/fonts/*.woff2 "$ROOT"/internal/portal/static/fonts/*-OFL.txt "$OUT/assets/fonts/"
cp "$ROOT/internal/portal/static/hero.webp" "$OUT/assets/"
for s in inventory cert inspect; do
  cp "$ROOT/docs/screenshots/$s.png" "$OUT/assets/screenshots/"
done
touch "$OUT/.nojekyll"
echo "site built in $OUT"
