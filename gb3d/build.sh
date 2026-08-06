#!/usr/bin/env bash
# Build the gb3d web app (Gen1Recomp in the browser) into an offline-capable
# static site.
#
# It packs the gen1recomp engine into game.love, runs it through love.js
# (prebuilt LÖVE-on-WebAssembly, no emscripten toolchain needed), applies the
# small web patches this repo carries, and drops in the mobile shell (ROM
# picker + PWA + IDBFS save flushing).
#
# Usage:
#   ./build.sh                       # clone gen1recomp @ pin, patch, build
#   GEN1_SRC=/path/to/gen1recomp ./build.sh   # use an existing checkout
#   ./build.sh --pages               # also refresh docs/ for GitHub Pages
#
# Output: dist/ (and docs/ with --pages).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
SHELL_DIR="$HERE/shell"
PATCH="$HERE/patches/gen1recomp-web.patch"
PIN="aa6217e5811cf37108b6da628dc342a44638aac8"   # gen1recomp commit the patch targets
MEM="536870912"                                  # 512 MiB — Game Boy data + textures
PAGES=0
[ "${1:-}" = "--pages" ] && PAGES=1

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# 1. Obtain a patched gen1recomp checkout.
if [ -n "${GEN1_SRC:-}" ]; then
  SRC="$GEN1_SRC"
  say "using existing gen1recomp checkout: $SRC (assumed already patched)"
else
  SRC="$HERE/.gen1recomp"
  if [ ! -d "$SRC/.git" ]; then
    say "cloning gen1recomp @ $PIN"
    git clone --filter=blob:none https://github.com/bryanthaboi/gen1recomp "$SRC"
  fi
  git -C "$SRC" fetch --depth 1 origin "$PIN" 2>/dev/null || git -C "$SRC" fetch origin
  git -C "$SRC" checkout -q "$PIN"
  git -C "$SRC" checkout -q -- .
  say "applying web patch"
  git -C "$SRC" apply "$PATCH"
fi

# 2. Tooling: love.js (prebuilt runtime; needs only Node).
if ! command -v npx >/dev/null; then echo "error: Node/npx required" >&2; exit 1; fi
if [ ! -x "$HERE/node_modules/.bin/love.js" ]; then
  say "installing love.js"
  ( cd "$HERE" && npm init -y >/dev/null 2>&1 || true; npm install love.js >/dev/null 2>&1 )
fi

# 3. Pack the engine into game.love (no ROM, no generated data).
say "packing game.love"
bash "$SRC/scripts/pack_love.sh" --output "$HERE/game.love" >/dev/null

# 4. love.js -> WebAssembly build. -c = compatibility (single-thread, no
#    SharedArrayBuffer) so it runs on GitHub Pages / mobile Safari without
#    cross-origin-isolation headers.
say "running love.js (compatibility, ${MEM} bytes)"
rm -rf "$DIST"
"$HERE/node_modules/.bin/love.js" -c -m "$MEM" -t "gb3d" "$HERE/game.love" "$DIST" >/dev/null 2>&1

# 5. Expose the emscripten FS on Module so the shell can hand the picked ROM to
#    the Lua importer (love.js does not export FS by default).
say "patching love.js: expose Module.FS"
sed -i 's/Module\["FS_createDataFile"\]=FS.createDataFile/Module["FS"]=FS;Module["FS_createDataFile"]=FS.createDataFile/' "$DIST/love.js"
grep -q 'Module\["FS"\]=FS;' "$DIST/love.js" || { echo "error: FS-expose patch did not apply (love.js template changed)" >&2; exit 1; }

# 6. Install the mobile shell (replaces love.js's default index.html).
say "installing shell (ROM picker + PWA + save flush)"
cp "$SHELL_DIR/index.html"           "$DIST/index.html"
cp "$SHELL_DIR/manifest.webmanifest" "$DIST/manifest.webmanifest"
cp "$SHELL_DIR/sw.js"                "$DIST/sw.js"
cp "$SHELL_DIR/icon-512.png"         "$DIST/icon-512.png"

say "build complete: $DIST ($(du -sh "$DIST" | cut -f1))"

# 7. Optionally stage into docs/ for GitHub Pages (deploy-from-branch).
if [ "$PAGES" = "1" ]; then
  say "staging into docs/ for GitHub Pages"
  rm -rf "$HERE/docs"
  mkdir -p "$HERE/docs"
  cp -R "$DIST/." "$HERE/docs/"
  touch "$HERE/docs/.nojekyll"
  say "docs/ ready"
fi
