# Gen1Recomp — Web (no-install) build

Runs [bryanthaboi/gen1recomp](https://github.com/bryanthaboi/gen1recomp) — the
native LÖVE2D recreation of Pokémon Red/Blue/Yellow, **including its 3D “tilt”
mode** — as a **web page**, so it can be played on an iPhone in Safari with
**no app install, no sideloading, no Apple ID**. You bring your own legal `.gb`
ROM; it’s verified and decoded on-device and never uploaded.

This exists because installing the native app requires sideloading (SideStore /
TrollStore / a computer). A browser page is the only way to run gen1recomp on a
stock iPhone with nothing installed.

## What this is (and the one honest caveat)

The build is produced with [love.js](https://github.com/Davidobot/love.js),
which compiles LÖVE to WebAssembly. It runs the **real gen1recomp engine**, not
a reimplementation.

- **Verified working** (in headless Chromium, this repo’s CI-style tests):
  boots to the ROM launcher, imports/verifies a ROM through the engine’s own
  SHA-1 path, **works fully offline** (installable PWA), and **persists saves +
  the imported game** across reloads (IndexedDB).
- **Not verifiable here — you must test it on your iPhone:** the frame rate of
  the **3D mode**. love.js runs **plain Lua 5.1 (no LuaJIT/JIT)**, so the engine
  logic runs interpreted. The 3D tilt is GPU/shader-based (cheap on CPU), so it
  has a real chance of being smooth on a modern iPhone — but only you, on your
  device with your ROM, can confirm it. If it’s choppy, the reliable path to
  smooth 3D is the native app (which needs an install).

## Use it on your iPhone

1. Open the deployed URL (see **Deploy** below) in **Safari**.
2. Tap **Choose ROM** and pick your clean US Red/Blue/Yellow `.gb`/`.gbc`
   (exactly 1 MiB). It’s verified on-device and imported in a few seconds.
3. Play. On-screen touch controls are enabled for the web build. In
   **Options → Colors / Tilt** turn on the **3D tilt** — that’s the thing to
   judge for smoothness.
4. **Share → Add to Home Screen** to get a fullscreen, offline launcher icon.
   Saves and your imported game are kept in the browser’s storage.

> Nothing is uploaded. The ROM is read in the browser, decoded to a private
> cache, then discarded. Supply only a ROM you’re legally entitled to.

## Deploy (get a URL)

The prebuilt site is committed to **`docs/`** at the repo root, so the simplest
path needs no CI:

**GitHub → Settings → Pages → Build and deployment → Source: “Deploy from a
branch” → Branch: `claude/iphone-rom-emulation-wjm9cq`, folder `/docs` → Save.**

After a minute the game is live at `https://<you>.github.io/fieldkit/`.

Alternatively, enable **Source: “GitHub Actions”** to build from source on every
push (workflow: `.github/workflows/gen1recomp-web-pages.yml`).

## Rebuild from source

```bash
# Clones gen1recomp @ the pinned commit, applies the web patch, builds with
# love.js, and assembles the site. Add --pages to also refresh docs/.
gen1recomp-web/build.sh --pages
```

Requirements: Node (for the `love.js` npm package — no emscripten toolchain
needed) and `zip`. Output lands in `gen1recomp-web/dist/` (and `docs/`).

## Layout

| Path | Role |
|------|------|
| `shell/index.html` | Mobile shell: ROM file-picker, PWA meta, IDBFS save flushing |
| `shell/manifest.webmanifest`, `shell/sw.js`, `shell/icon-512.png` | PWA manifest, offline service worker, icon |
| `patches/gen1recomp-web.patch` | The engine changes below, against gen1recomp `aa6217e` |
| `build.sh` | Pack → love.js → expose FS → install shell |
| `../docs/` | Prebuilt site for GitHub Pages |

## What the patch changes, and why

love.js runs LÖVE on **Lua 5.1 in a browser**, which differs from the native
LuaJIT builds in a few ways the engine assumes. The patch is small, contained to
the web platform, and leaves native builds untouched:

1. **`love.filesystem.read` hangs on a missing file** in love.js (it logs
   “Could not open file … Does not exist.” and never returns, freezing boot —
   the launcher probes not-yet-created cache/option files every start).
   `getInfo` is safe, so on Web every read is gated behind an existence check.
2. **No `bit` library.** LÖVE normally runs LuaJIT, whose `bit` module the ROM
   extractor, save code and audio synth `require`. A pure-Lua, LuaBitOp-
   compatible `bit` (`src/compat/luabit.lua`, known-answer-tested) is registered
   under the same name on Web.
3. **ROM import on the web.** There’s no native file picker or working
   drag-drop, so the shell writes the chosen ROM to a fixed path in the
   emscripten FS and a small web poll (`RomImporter:_pollWebRom`) reads it via
   Lua `io` (PhysFS caches the save dir and wouldn’t see the out-of-band write)
   and routes it through the engine’s normal verified import.
4. **Touch controls on the web.** The on-screen overlay and the launcher’s
   touch-tap handling now treat `getOS() == "Web"` like a phone, so the game is
   playable by touch in mobile Safari.

The build also patches the generated `love.js` to expose `Module.FS` (so the
shell can hand over the ROM) and flushes IDBFS to IndexedDB on a timer and on
page hide (so saves survive).

## Limitations

- **3D smoothness is unverified on real iOS hardware** (see the caveat above).
- Audio uses the same interpreted-Lua synth; it may be heavier than on native.
- Only canonical **1 MiB US** Red/Blue/Yellow ROMs import (same SHA-1 gate as
  every gen1recomp build).
- Built against gen1recomp `aa6217e`; newer upstream changes may need the pin
  and patch refreshed.
