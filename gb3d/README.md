# gb3d — Game Boy Pokémon in 3D, in your browser

A **no-install** way to play [bryanthaboi/gen1recomp](https://github.com/bryanthaboi/gen1recomp)
— the native LÖVE2D recreation of Pokémon Red/Blue/Yellow, **including its 3D
“tilt” mode** — as a **web page**. It runs on a stock iPhone in Safari with **no
app install, no sideloading, no Apple ID**. You bring your own legal `.gb` ROM;
it’s verified and decoded on-device and never uploaded.

> **Not an emulator.** Emulators (Delta, Folium, RetroArch) run the original
> Game Boy code and draw the flat 2D screen — they can’t produce 3D, because 3D
> isn’t an emulation feature. gb3d runs gen1recomp’s real engine, which
> reimplements the game world with actual 3D geometry.

## What this is (and the one honest caveat)

The build is produced with [love.js](https://github.com/Davidobot/love.js),
which compiles LÖVE to WebAssembly. It runs the **real gen1recomp engine**.

- **Verified working** (headless Chromium): boots to the ROM launcher, imports
  and verifies a ROM through the engine’s own SHA-1 path, **works fully offline**
  (installable PWA), and **persists saves + the imported game** across reloads
  (IndexedDB).
- **Only you can confirm the 3D frame rate**, on your iPhone, with a real ROM.
  love.js runs **plain Lua 5.1 (no LuaJIT/JIT)**, so engine logic runs
  interpreted. The 3D tilt is GPU/shader-based (cheap on CPU), so it has a real
  shot at being smooth on a modern iPhone — but that’s the thing to test. If
  it’s choppy, the reliable path to smooth 3D is the native gen1recomp app
  (see [NATIVE-APP-ALTERNATIVE.md](NATIVE-APP-ALTERNATIVE.md)).

## Use it on your iPhone

1. Open the deployed URL (see **Deploy** below) in **Safari**.
2. Tap **Choose ROM** and pick your clean US Red/Blue/Yellow `.gb`/`.gbc`
   (exactly 1 MiB). It’s verified on-device and imported in a few seconds.
3. Play with the on-screen touch controls. In **Options** turn on the **3D
   tilt** — that’s the thing to judge for smoothness.
4. **Share → Add to Home Screen** for a fullscreen, offline launcher icon.
   Saves and your imported game are kept in the browser’s storage.

> Nothing is uploaded. The ROM is read in the browser, decoded to a private
> cache, then discarded. Supply only a ROM you’re legally entitled to.

## Deploy (get a URL)

The prebuilt site is committed to **`docs/`**, so the simplest path needs no CI:

**Settings → Pages → Build and deployment → Source: “Deploy from a branch” →
Branch: `main`, folder `/docs` → Save.**

After a minute the game is live at `https://<you>.github.io/gb3d/`.

Alternatively, enable **Source: “GitHub Actions”** to build from source on every
push (workflow: `.github/workflows/pages.yml`).

## Rebuild from source

```bash
./build.sh --pages
```

Requirements: Node (for the `love.js` npm package — no emscripten toolchain
needed) and `zip`. Clones gen1recomp @ the pinned commit, applies the web patch,
builds, and assembles the site into `dist/` (and `docs/`).

## Layout

| Path | Role |
|------|------|
| `shell/index.html` | Mobile shell: ROM file-picker, PWA meta, IDBFS save flushing |
| `shell/manifest.webmanifest`, `shell/sw.js`, `shell/icon-512.png` | PWA manifest, offline service worker, icon |
| `patches/gen1recomp-web.patch` | The engine changes below, against gen1recomp `aa6217e` |
| `build.sh` | Pack → love.js → expose FS → install shell |
| `docs/` | Prebuilt site for GitHub Pages |
| `NATIVE-APP-ALTERNATIVE.md` | How to sideload the native app (smooth 3D, needs an install) |

## What the patch changes, and why

love.js runs LÖVE on **Lua 5.1 in a browser**, which differs from native LuaJIT
builds. The patch is small, contained to the web platform, and leaves native
builds untouched:

1. **`love.filesystem.read` hangs on a missing file** in love.js (freezes boot,
   because the launcher probes not-yet-created cache/option files every start).
   `getInfo` is safe, so on Web every read is gated behind an existence check.
2. **No `bit` library.** LÖVE normally runs LuaJIT, whose `bit` module the ROM
   extractor, save code and audio synth `require`. A pure-Lua, LuaBitOp-
   compatible `bit` (`src/compat/luabit.lua`, known-answer-tested) is registered
   under the same name on Web.
3. **ROM import on the web.** No native picker or working drag-drop, so the shell
   writes the chosen ROM to a fixed path in the emscripten FS and a small web
   poll (`RomImporter:_pollWebRom`) reads it via Lua `io` (PhysFS caches the save
   dir and wouldn’t see the out-of-band write) and routes it through the
   engine’s normal verified import.
4. **Touch controls on the web.** The on-screen overlay and the launcher’s
   touch-tap handling now treat `getOS() == "Web"` like a phone.

The build also patches the generated `love.js` to expose `Module.FS`, and the
shell flushes IDBFS to IndexedDB on a timer and on page hide (so saves survive).

## Credits & licensing

The engine is [bryanthaboi/gen1recomp](https://github.com/bryanthaboi/gen1recomp)
— all game logic and the 3D renderer are theirs. This repo only adds the web
packaging (love.js build, the web-compat patch, and the browser shell). See the
gen1recomp repository for its license. gb3d ships **no ROM** and no game data.

## Limitations

- **3D smoothness is unverified on real iOS hardware** (see the caveat above).
- Audio uses the same interpreted-Lua synth; it may be heavier than on native.
- Only canonical **1 MiB US** Red/Blue/Yellow ROMs import.
- Built against gen1recomp `aa6217e`; newer upstream may need the pin/patch
  refreshed.
