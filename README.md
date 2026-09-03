# ElriaGame.exe — Exastealer dissection

Static analysis of a Windows installer distributed as `ElriaGame.exe` that turns
out to be a delivery wrapper for **Exastealer v1.0**, a Java-based information
stealer. This repo contains the write-up, indicators, and the unpacker /
deobfuscator scripts. **No malware binaries are included** — see
[`SAMPLES.md`](SAMPLES.md) for hashes and how to obtain the sample.

Nothing here was executed; the whole analysis is static, on macOS.

## TL;DR

| item | value |
|---|---|
| Family | Exastealer v1.0 (self-labeled in JAR manifest) |
| Delivery | NSIS installer wrapping an Electron app |
| Dropper | `launcher1.js` inside `app.asar`, 4-layer XOR/subtract obfuscation |
| Payload | `emre.jar` (Java) + private JRE, AES-encrypted inside `data.7z` |
| Archive password | `7zgw3s6kxCZi` (hard-coded in stage-4) |
| Install dir | `%LOCALAPPDATA%\emre\` |
| Persistence | `HKCU\...\Run\emre` = `javaw -jar %LOCALAPPDATA%\emre\emre.jar --startup` |
| Stealth | 0×0 window, `skipTaskbar`, prevents-quit, self-respawn, auto-restart ≤ 2× |
| Capabilities | JNA bindings for DPAPI (`MyCrypt32`), NCrypt (Chromium master-key unwrap), Firefox NSS (`PK11SDR_Decrypt`), SQLite (Chromium cookie/login DBs), Steam and Discord token stealing, browser wallet extension theft (61 extensions), 48 desktop wallets, plus **elevation-moniker UAC bypass in `peynir.dll`** |
| Exfil | okhttp3 + Apache HttpClient 5 + java-websocket → `http://52.249.219.108:3001` (WebSocket URL not recovered) |
| Locale hint | "emre" (Turkish given name), "peynir" (Turkish "cheese") |

## Delivery chain

```
ElriaGame.exe  (NSIS SFX, 146 MB)
├─ $PLUGINSDIR/
│   ├─ nsis7z.dll, StdUtils.dll, System.dll   (stock NSIS plugins)
│   └─ app-64.7z                              (electron-builder payload)
└─ (extracted from app-64.7z; siblings at top level:)
   ├─ ElriaGame.exe                           (Electron shell, 235 MB)
   ├─ Chromium DLLs, resources.pak, locales/, chrome_*_percent.pak, etc.
   └─ resources/
      ├─ app.asar                             (62 KB — thin launcher)
      │   └─ launcher1.js                     (obfuscated dropper)
      ├─ app.asar.unpacked/                   (7zip-bin per-arch binaries)
      ├─ 7za.exe, 7za-ia32.exe                (bundled 7-Zip CLI)
      ├─ elevate.exe                          (UAC-elevate helper — unused by launcher)
      └─ data.7z                              (7zAES-encrypted)
          ├─ emre.jar                         (Exastealer, 42.6 MB)
          └─ jre.zip                          (private JRE)
```

## Stage-1 through stage-4: the JS dropper

`app.asar` is trivial:

```json
{ "name": "elriagame", "main": "launcher1.js", "dependencies": { "7zip-bin": "^5.2.0" } }
```

`launcher1.js` is one line — a base64 blob plus a tiny decoder that
`eval`s the result. The decoder is the same three-parameter routine at every
layer:

```js
function decode(d, k, r) {
  var b  = Buffer.from(d, 'base64');
  var kb = Buffer.from(k, 'utf8');          // key is a 64-char hex STRING, used as UTF-8 bytes
  for (var i = 0; i < b.length; i++) {
    b[i] = (((b[i] - r - i) ^ kb[(i + r) % kb.length]) & 0xFF);
  }
  return b.toString('utf8');
}
eval(decode(_blob, _key, _rot));
```

Four nested layers, each identical shape, distinct `(key, r)`:

| layer | rotation `r` | key prefix | output size |
|---|---:|---|---:|
| 1 | 53  | `6186c1c2b8…` | 42 807 B |
| 2 | 254 | `e8b1d21197…` | 31 750 B |
| 3 | 55  | `5a657a1b4e…` | 23 459 B |
| 4 | 187 | `03cc5f8dbf…` | 17 193 B |

Stage-4 is plain, readable Node.js — see `scripts/peel_launcher.js` for a
one-shot peeler that dumps every intermediate stage without ever `eval`ing.

### Stage-4 behavior (509 lines, beautified)

Constants:

```js
var APP_NAME         = "emre";
var ARCHIVE_PASSWORD = "7zgw3s6kxCZi";       // Injected during build
var MAX_RESTARTS     = 2;
```

Flow, in order:

1. **Hide the window.** Because this ships as an Electron app, it must open
   *some* window. It opens one that is 0×0, `skipTaskbar: true`, `frame: false`;
   calls `app.dock.hide()`; and intercepts `before-quit` with `e.preventDefault()`.
2. **Detach into a hidden clone.** First run spawns a copy of itself with
   `_HIDDEN_MARKER=1` in the environment and `windowsHide: true`, then exits
   the parent 500 ms later. The clone re-enters and runs `main()`.
3. **Copy `data.7z`** from `process.resourcesPath` to `%LOCALAPPDATA%\emre\`.
4. **Extract with the hard-coded password** by shelling out to a bundled
   `7za.exe` (looked up in several places, then cached as
   `%LOCALAPPDATA%\emre\data_helper.exe`). Args are constructed with `-p<pwd>`
   spliced in only when `ARCHIVE_PASSWORD` is set.
5. **Extract `jre.zip`** into `%LOCALAPPDATA%\emre\jre\` so the malware carries
   its own JRE and does not depend on a system Java.
6. **Delete `data.7z`** and `jre.zip` after extraction.
7. **Persist.** Writes the HKCU Run key via `reg add`:
   ```
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
     emre = "<full-path>\javaw.exe" -jar "%LOCALAPPDATA%\emre\emre.jar" --startup
   ```
   The launcher resolves the full path to `javaw.exe` under the extracted
   JRE tree and prefers it over `java.exe` (no console window).
8. **Launch the JAR** with `child_process.spawn(java, ["-jar", jar], {stdio:"ignore", detached:true, windowsHide:true})`.
9. **Liveness watchdog.** 20 s after spawning, checks whether Java is still
   running by three methods (JAR file lock via `fs.openSync`, `tasklist` grep
   for `java.exe`, and a recently-touched `%TEMP%\debug.log`). If not, restarts
   itself up to `MAX_RESTARTS` times, propagating `_RESTART_COUNT` in the env.

There is no download step, no `http.get`, no `require('http')` — the delivery
is entirely offline. The C2 is inside the JAR.

## The JAR: Exastealer

`emre.jar` self-identifies:

```
Manifest-Version: 1.0
Main-Class: com.xc17edb19a.PLhWEEjyn
Implementation-Title: Exastealer
Implementation-Version: 1.0
```

Structural observations from the class list (4 539 `.class` files):

- Obfuscated main package `com.xc17edb19a.*` with dollar-suffixed inner classes
  named after Windows API objects: `MyCrypt32`, `NCrypt`, `ICMLuaUtil`,
  `TOKEN_ELEVATION`.
- `com.sun.jna.platform.win32.*` shipped in-JAR — JNA-backed direct calls to
  `Crypt32`, `NCrypt`, `WinCrypt`, `WinRas`, and mac/linux JNA (portability
  is present, though every path in the launcher assumes Windows).
- A `mozilla/` tree for Firefox NSS decryption.
- Networking stack: `okhttp3.*`, Apache HttpClient 5 (`org.apache.hc.*`),
  `org.java_websocket.*`.
- Native shim: `peynir.dll` (PE32+ x86-64) at the JAR root — a JNI wrapper
  around the **CMSTPLUA / `ICMLuaUtil` elevation-moniker UAC bypass**,
  called as `IvTHdVAG.nativeRunElevated(String cmd, String args)`. Full
  reverse in [`PEYNIR_DLL.md`](PEYNIR_DLL.md). Plus per-platform `native/*`
  `.so`/`.dll`/`.jnilib`/`.a` files. `peynir` is Turkish for cheese — matches
  `APP_NAME="emre"`.
- Four pre-styled HTML **lures** at the root: `beta-game-setup.html`,
  `fake-error.html`, `mc-client-setup.html`, `watch-setup.html` — all rendered
  as Windows-installer-lookalike dialogs while the stealer runs.

Before decryption, the only non-library URL anywhere in the JAR is the C2:

```
http://52.249.219.108:3001
```

Plain HTTP, nonstandard port. IP ASN / geolocation was not looked up in-session.
After JAR string decryption, three routes on this endpoint and two live
Discord API URLs surface — see [`IOCS.md`](IOCS.md) and
[`JAR_INTERNALS.md`](JAR_INTERNALS.md).

## Indicators of compromise

See [`IOCS.md`](IOCS.md) and [`HASHES.txt`](HASHES.txt).

## Reproducing the unpack

You need `sevenzip`, `node`, and `@electron/asar`. On macOS:

```bash
brew install sevenzip
scripts/unpack_installer.sh /path/to/ElriaGame.exe ./out
```

That gives you, under `./out/`:

- `app/` — the Electron app bundle (Chromium DLLs, resources, etc.)
- `asar-out/launcher1.js` — the obfuscated dropper source
- `stage-1.js` … `stage-4.js` — each layer of the JS decrypt
- `final.pretty.js` — beautified stage-4
- `data/emre.jar`, `data/jre.zip` — the Exastealer payload (kept OUT of git)
- `jar/` — the exploded JAR

The unpacker never runs the installer or the JAR. It writes the decrypted
launcher to disk rather than passing it to `eval`.

## The Java payload

The full reverse of `emre.jar` — obfuscator model, string-decrypt algorithm,
class map (obfuscated → intent), C2 protocol, target catalog (48 desktop
wallets, 61 browser wallet extensions, 5 browsers × 6 profiles, 90 file
extensions), Discord renderer injection, Task-Manager disable — is in
[`JAR_INTERNALS.md`](JAR_INTERNALS.md). The two deobfuscation tools
(`scripts/dump_tables.java` and `scripts/deobfuscate_strings.py`) reproduce
it locally against the sample.

## Repository policy

This repo carries the **write-up and tooling only**. `emre.jar`, `peynir.dll`,
`data.7z`, and `ElriaGame.exe` itself are deliberately not published here —
they are live malware, and hosting them would help operators as much as
defenders. Hashes are in `HASHES.txt` so you can verify a sample obtained
elsewhere (MalwareBazaar, VirusTotal, an incident response) matches the one
this write-up describes. If you need the samples for defensive research and
cannot find them by hash, open an issue.

## License

MIT — see [`LICENSE`](LICENSE).
