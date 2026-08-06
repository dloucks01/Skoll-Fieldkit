# Running Gen1Recomp on your iPhone

A step-by-step for getting [bryanthaboi/gen1recomp](https://github.com/bryanthaboi/gen1recomp)
onto an iPhone and importing a ROM that already lives in the phone's Files
app. Tailored to an **iPhone-only** setup (no daily computer) using the
**easiest, self-updating** install route.

> There is **nothing to build or code**. Gen1Recomp already publishes a
> finished iOS app and an in-app ROM importer. This is an install-and-import
> task, not a compile task.

---

## What Gen1Recomp actually is (read this first)

- It is **not** a Game Boy emulator and it does **not** contain a ROM. It is a
  hand-written [LÖVE2D](https://love2d.org/) (Lua) re-creation of the Gen 1
  Pokémon engine.
- On first launch it asks for **your own legally obtained** US `.gb` / `.gbc`
  ROM. It **verifies the ROM's SHA-1**, decodes the game data and graphics into
  a private on-device cache, then **releases the ROM from memory**. The ROM is
  not copied or redistributed. Later launches use the cache and never ask again.
- Red, Blue, and Yellow can all be imported and played side by side.

Only the canonical **1 MiB US** ROMs are accepted. The importer checks these
SHA-1 hashes:

| Game   | SHA-1 |
| ------ | ----- |
| Red    | `ea9bcae617fdf159b045185467ae58b2e4a48b9a` |
| Blue   | `d7037c83e1ae5b39bde3c30787637ba1d4c48ce2` |
| Yellow | `cc7d03262ebfaf2f06772c1a480c7d9d5f4a38e1` |

If your file is a different region, a `.zip`, a trimmed/over-dumped cart, or
not exactly 1 MiB, it will be rejected safely — nothing gets imported.

---

## The one honest caveat about "no computer at all"

iOS won't run unsigned apps, so a sideloaded app has to be signed. There are
exactly two ways to bootstrap that **without owning a Mac**:

1. **TrollStore** — if your iPhone's iOS version is eligible, this is the best
   option by far: the app installs **permanently**, with **no 7-day expiry**
   and **no Apple ID needed**. Some iOS versions can even install TrollStore
   fully on-device.
2. **SideStore / AltStore** — works on any modern iOS, re-signs the app with
   your **free Apple ID**, and refreshes **wirelessly on-device** afterward.
   The catch: the **very first** install of the sideloader needs a **one-time**
   touch of *a* computer (yours, a friend's, a library PC). After that first
   bootstrap you never need a computer again.

> Tools that advertise "100% no PC" (e.g. *SideInstaller*) still require you to
> sideload **that tool itself** once by some other means — so the one-time
> computer requirement doesn't actually go away unless you're TrollStore-eligible.

**So your iOS version decides your path.** Check it first.

---

## Step 0 — Check your iOS version

**Settings → General → About → Software Version.**

- **iOS 14.0 – 16.6.1**, **16.7 RC (build 20H18)**, or **17.0** →
  **TrollStore-eligible → use Path A** (permanent, no computer, no refresh).
- **iOS 17.0.1 or newer** (17.x, 18, 26, …) →
  **not TrollStore-eligible → use Path B** (SideStore, one-time computer, then
  wireless auto-refresh).

Apple patched the TrollStore exploit in 17.0.1, so newer devices can't use it.

---

## Path A — TrollStore (eligible devices): permanent, no expiry

1. Install TrollStore using the official guide for your exact version:
   **https://ios.cfw.guide/installing-trollstore/**
   (Pick the installer it lists for your build. Several versions install
   directly on the phone.)
2. On the phone, open **Safari** and go to the Gen1Recomp
   [Releases page](https://github.com/bryanthaboi/gen1recomp/releases/latest).
3. Download the latest **`gen1recomp-*-ios.ipa`** asset.
4. Tap the downloaded IPA → **Open in TrollStore** → **Install**.
5. Launch **gen1recomp**. Done — it never expires and needs no Apple ID.

> With TrollStore you can install the IPA directly, so you don't strictly need
> SideStore. If you still want the tidy "add a source, get updates" experience,
> you can install SideStore/AltStore *through* TrollStore and follow Path B's
> "Install the game" section — but for most people, direct-install is simpler.

Then jump to **Import your ROM** below.

---

## Path B — SideStore (not TrollStore-eligible): easiest self-updating route

This is the route you picked. One-time bootstrap, then it maintains itself
wirelessly.

### B1. One-time: get SideStore onto the phone

You need *a* computer for this single step. Two common ways:

- **AltServer (Windows/Mac):** Install AltStore/SideStore by following the
  official guide — [Windows](https://faq.altstore.io/altstore-classic/how-to-install-altstore-windows)
  · [macOS](https://faq.altstore.io/altstore-classic/how-to-install-altstore-macos).
  This installs the app and generates the **pairing file** SideStore needs.
- **SideStore's own docs:** https://sidestore.io/ — follow their current
  "getting started" (pairing file + install). Their steps track iOS changes
  more closely than any third-party writeup.

After install, SideStore uses an on-device VPN (e.g. **StosVPN**) purely as a
local loopback so it can re-sign apps **on the phone** — no computer needed for
refreshes from here on.

### B2. Add the Gen1Recomp source

The project publishes an official app repo. On the phone, either:

- **One-tap:** open this link in Safari and let it hand off to SideStore —
  `https://intradeus.github.io/http-protocol-redirector?r=sidestore://source?url=https://github.com/bryanthaboi/gen1recomp/raw/refs/heads/main/mobile/ios/app-repo.json`
- **Manually:** SideStore → **Browse / Sources → + (Add Source)** → paste:
  `https://github.com/bryanthaboi/gen1recomp/raw/refs/heads/main/mobile/ios/app-repo.json`

(AltStore and Feather use the same URL; the README has one-tap badges for each.)

### B3. Install the app

1. Open the **gen1recomp** source in SideStore and tap **Install / Get**
   (latest is **v0.1.64**, ~9 MB).
2. Sign in with your **free Apple ID** if prompted (used locally for signing).
3. First launch only: **Settings → Privacy & Security → Developer Mode** (turn
   on, iOS 16+), and **Settings → General → VPN & Device Management** → trust
   your Apple ID certificate if asked.

---

## Import your ROM (it's already in Files)

This is the part you specifically asked about, and the iOS build was designed
for exactly it. **Two built-in ways** — either works:

### Method 1 — In-app picker (browse to it)

1. Open **gen1recomp**. On the first-boot launcher, pick the **Red / Blue /
   Yellow** tab you want.
2. Tap **Import ROM**. The iOS document picker opens.
3. Browse to wherever your `.gb` lives in **Files** (On My iPhone, iCloud
   Drive, a folder, wherever) and select it.
4. Import takes a few seconds — the ROM is verified, the cache is built, and
   the game starts.

### Method 2 — Drop it into the app's folder (auto-import)

1. Open the **Files** app → **On My iPhone** → **gen1recomp** folder.
2. Copy or move your `.gb` / `.gbc` (or a `.sav` battery save, or a `.zip` mod)
   into that folder.
3. Reopen **gen1recomp**. On launch it **sweeps that folder automatically**,
   moves the ROM in, and imports it with no extra taps.

Repeat for each version (Red/Blue/Yellow) you want. Once imported, you can
delete the loose ROM file — the game runs from its own private cache.

---

## First run: controls, performance, saves

- **Controls:** on-screen touch buttons by default; rebind under
  **Options → Controls**. A paired game controller also works.
- **Performance:** **Options → Performance** defaults to **AUTO**, which picks
  **BALANCED** on phones (drops 3D tilt / GBC FX for smoothness). The actual
  game logic is identical on every tier. Bump to **HIGH** on a newer iPhone if
  you want the extras.
- **Saves:** in-game save/load plus battery saves live in the app's private
  storage and **survive app refreshes**. You can export a `.sav` back out
  through the share/export picker.

---

## Keeping it alive & troubleshooting

- **7-day expiry (SideStore/free Apple ID):** the app stops launching after 7
  days until re-signed. SideStore refreshes it **wirelessly on its own** as long
  as it can reach the phone (VPN enabled, occasionally open SideStore).
  **TrollStore installs never expire.**
- **Updating the game:** SideStore shows new versions from the source — tap
  update. On TrollStore, download the newer IPA from Releases and re-open it in
  TrollStore.
- **"Import ROM does nothing":** make sure you're on the latest build (an older
  iOS picker bug is fixed in current releases), confirm the file is a real
  **1 MiB US** ROM matching a SHA-1 above, and try **Method 2** (drop-in) as a
  fallback.
- **App won't open after a while:** it expired — open SideStore and refresh.

---

## Legal note

Gen1Recomp ships **no ROM** and redistributes none. You must supply a ROM you
are legally entitled to (e.g. dumped from a cartridge you own). The app only
reads game data out of the file you provide.

---

## Sources

- Gen1Recomp repo & README: https://github.com/bryanthaboi/gen1recomp
- Maintainer's sideload doc: `docs/ios-sideload.md` in the repo
- Official app-repo source: `mobile/ios/app-repo.json` in the repo
- TrollStore install guide: https://ios.cfw.guide/installing-trollstore/
- SideStore: https://sidestore.io/
- AltStore install: https://faq.altstore.io/
