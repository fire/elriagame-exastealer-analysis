# Logbook: methods and apparatus

An honest record of what was measured, in the order it was measured, so
someone else can re-run the same static dissection and get the same result.

## Sample

- Filename: `ElriaGame.exe`, 146 758 741 bytes.
- SHA-256: `319acc0f884b20f8c36c03912996c98f7860abf99d39e7492775c0320ae9e00d`.
- `file(1)` reports: `PE32 executable (GUI) Intel 80386, for MS Windows,
  Nullsoft Installer self-extracting archive`.
- Delivered to the analyst's Downloads folder; handed off as
  "treat as malware."
- The whole analysis is static, on macOS (Apple silicon, `arm64_tahoe`).
  Nothing was executed at any point — no Wine, no VM boot, no `java -jar`
  on the payload.

## Apparatus

Host tools, versions as observed:

| tool | version | purpose |
|---|---|---|
| `sevenzip` (7zz) | 26.02 arm64 | unpack NSIS SFX, `app-64.7z`, `data.7z` |
| `node`, `npx`  | system Node | run `@electron/asar extract` and the peel script |
| `@electron/asar` | latest via `npx --yes` | extract `app.asar` |
| `js-beautify` | latest via `npx --yes` | pretty-print each decrypted stage |
| Apple `strings`, `file`, `shasum -a 256` | Xcode CLT | triage |
| Apple `objdump` (LLVM) | Xcode CLT | PE header + disassembly of `peynir.dll` |
| `openjdk` | 26.0.2.1 (Homebrew) | run CFR |
| CFR | 0.152 (Maven Central `cfr-0.152.jar`) | decompile `com.xc17edb19a.*` |
| `git`, `gh` | authenticated as `fire` | publish the analysis repo |

Everything ran under the session's scratchpad; no artifact was written into
the user's project tree or committed to git.

## Method, in order

Each step's rationale is one sentence and each step's result is a number, a
hash, or a decision.

1. **Hash and identify.** `shasum -a 256` + `file` on the installer. The
   `Nullsoft Installer self-extracting archive` classification decided the
   next tool: `7z x` unpacks NSIS SFX without executing it.
2. **Unpack the NSIS layer.** `7zz x` into a per-run scratchpad. Result: four
   files in `$PLUGINSDIR/` — three stock NSIS plugin DLLs (`nsis7z.dll`,
   `StdUtils.dll`, `System.dll`, hashed for provenance) and a 140 MB
   `app-64.7z`, which is the electron-builder payload shape.
3. **Unpack the electron-builder payload.** `7zz x app-64.7z`. Result: a
   standard Electron-32 tree — Chromium DLLs, `locales/`, `resources/`,
   plus an Electron shell renamed `ElriaGame.exe` (224 MB).
4. **Enumerate the Electron resources.** In `resources/`, four items were
   novel next to a stock electron-builder tree: `data.7z` (41 MB, 7z magic),
   two bundled `7za.exe` variants (x64 and ia32), `elevate.exe`, and a
   62 KB `app.asar` — the last is unusually small for a real game.
5. **Decide `data.7z`'s status without opening it.** `7zz l data.7z`
   returned `Enter password:` — the archive is 7zAES-encrypted. This was the
   first strong red flag: legitimate installers rarely password-protect the
   payload they need to extract on the target machine, because it defeats
   AV scanning during install.
6. **Extract `app.asar`.** `npx --yes @electron/asar extract`. Result: two
   real files (`launcher1.js` at 57 KB, `package.json` at 8 lines) plus
   vendored `node_modules/7zip-bin/`. The package's `main` is `launcher1.js`
   and `description` is empty — no game, one launcher.
7. **Look at `launcher1.js`.** One line, one 57 076-byte base64-ish string,
   and a `Buffer.from`-based function eval'd on the result. The decoder is:
   ```
   b[i] = ((b[i] - r - i) XOR key[(i + r) mod |key|]) & 0xff
   ```
   with `key` a 64-char hex string used verbatim as UTF-8 bytes and `r` an
   integer rotation. `js-beautify` on it kept it at 13 lines — everything
   interesting is inside a base64 blob.
8. **Peel the layers.** Rather than call `eval`, an equivalent Node one-liner
   applied the decode and wrote the result to disk, then re-matched the
   same shape on the output. Four passes stripped four layers before the
   pattern stopped matching:

   | layer | rotation `r` | key prefix | output size (bytes) |
   |---|---:|---|---:|
   | 1 | 53  | `6186c1c2b8…` | 42 807 |
   | 2 | 254 | `e8b1d21197…` | 31 750 |
   | 3 | 55  | `5a657a1b4e…` | 23 459 |
   | 4 | 187 | `03cc5f8dbf…` | 17 193 |

   The peel script is committed as `scripts/peel_launcher.js` — negative
   control: it will NOT call `eval`, and stops when the shape no longer
   matches rather than looping forever.
9. **Read stage-4.** Beautified to 509 lines. This is the dropper. Two
   constants named the whole thing: `APP_NAME = "emre"` and
   `ARCHIVE_PASSWORD = "7zgw3s6kxCZi"` with the author's own comment
   "Injected during build." Behavior: hide the Electron window at 0×0,
   respawn detached with `_HIDDEN_MARKER=1`, copy `data.7z` to
   `%LOCALAPPDATA%\emre\`, extract with the recovered password, extract
   `jre.zip` alongside for a private JRE, delete both archives, write
   `HKCU\...\Run\emre` for persistence, `spawn(javaw, ["-jar", emre.jar])`
   detached and hidden, then a 20-second liveness watchdog with three
   independent checks (file-lock on the JAR, `tasklist` grep for
   `java.exe`, `%TEMP%\debug.log` recency) and up to 2 restarts.
10. **Open `data.7z` with the recovered password.** `7zz x -p'7zgw3s6kxCZi'`
    succeeded and yielded exactly two files: `emre.jar` (42.6 MB) and
    `jre.zip`. The JAR's SHA-256 is
    `33f0ac160b6807c7e70015a148ac4ddfe89341c7a8b8454234afc3c3b2060712`.
11. **Enumerate the JAR without decompiling.** `unzip -l | awk` for
    extensions and root packages, `unzip -p META-INF/MANIFEST.MF` for
    identity. The manifest self-identified:
    `Implementation-Title: Exastealer`, `Implementation-Version: 1.0`,
    `Main-Class: com.xc17edb19a.PLhWEEjyn`. 4 539 `.class` files. Author
    package `com.xc17edb19a` alongside `okhttp3`, Apache HttpClient 5,
    `com.sun.jna.platform.*`, a `mozilla/` NSS tree, `org.java_websocket`,
    four HTML lure files at the root, and one native binary named
    `peynir.dll`.
12. **Find the C2 without executing.** `grep -aroEh 'https?://…'` over the
    exploded tree, filtered against a stock allowlist of stdlib/ICU
    registry URLs. Exactly one non-library URL survived:
    `http://52.249.219.108:3001`. WHOIS puts 52.249.0.0/16 in Microsoft
    Azure (`MSFT`, ASN 8075). Plain HTTP, nonstandard port.
13. **Confirm the JAR is Exastealer, not just self-labeled.** The class
    surface matches: JNA-imported `MyCrypt32` and `NCrypt` inner classes
    (DPAPI unwrap for Chrome/Edge browser cookies and passwords), a
    `mozilla/` tree (Firefox NSS), `TOKEN_ELEVATION` (elevation-check
    scaffolding), okhttp3 + Apache HC5 + java-websocket (multi-channel
    exfil), four pre-styled HTML dialogs (`beta-game-setup.html`,
    `fake-error.html`, `mc-client-setup.html`, `watch-setup.html`) whose
    titles telegraph the social-engineering surface.
14. **Reverse `peynir.dll` by hand.** LLVM `objdump -x -p` for headers and
    imports, `objdump -d --disassemble-symbols=…` for the two JNI exports.
    The header is trivially not packed: real `.text`/`.rdata`/`.data`
    sections, real IAT, real relocs, `GUARD_CF`. Exports: `JNI_OnLoad`
    (RVA 0x16b0) and
    `Java_com_xc17edb19a_IvTHdVAG_nativeRunElevated` (RVA 0x1470). The
    `nativeRunElevated` prologue peels two `jstring` args via JNIEnv
    slots `+0x528`/`+0x520` (`GetStringUTFChars`/`GetStringUTFLength`)
    and forwards them to `sub_1800011c0`.
    That core does three things in order:
    - writes a fake `PEB->CurrentDirectory.Buffer` / `DllPath.Buffer` /
      `Ldr->InLoadOrderModuleList.Flink->FullDllName.Buffer` to a hardcoded
      `C:\Windows\System32\` wide string in `.rdata`, spoofing the
      "auto-elevate" whitelist that the AIS reads out of the caller's PEB;
    - XOR-assembles a 32-byte wide string on the stack from three 16-byte
      `.rdata` blobs, which is the elevation moniker
      `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`
      — CMSTPLUA (`ICMLuaUtil`);
    - `CoInitialize`, `CoGetObject` on the moniker, then `call [rax+0x48]`
      on the returned COM interface. Vtable slot 9 in `ICMLuaUtil` is
      `ShellExec`. Followed by `Release` (`+0x10`) and `CoUninitialize`.

    This is UACMe method 41 verbatim, packaged as a JNI helper.
15. **Choice not to use `flowref-decompiler` on the DLL.** Recorded
    honestly: the skill's I0 gate emits C only for modeled instruction
    classes and refuses on unmodeled paths, and this DLL's meaning lives
    entirely in indirect calls through an IAT and vtable dispatch through
    COM interfaces. Flowref would have refused the whole function, so the
    reverse was done by hand against the disassembly. This is the shape
    of the "state the detection floor" rule — a tool that would report
    "unmodeled" on every line is not what the picture needs.
16. **Publish the analysis.** `git init` in a scratch tree, LICENSE + README
    + IOCs + hashes + `PEYNIR_DLL.md` + peeler + shell orchestrator,
    `gh repo create fire/elriagame-exastealer-analysis --public --source=. --push`.
    Policy in `.gitignore` and README: no malware binary is committed;
    hashes only.
17. **Attempt to reverse the JAR body.** `brew install openjdk`, download
    `cfr-0.152.jar`, `java -jar cfr.jar --jarfilter '.*com\.xc17edb19a\..*'`.
    23 top-level classes from the obfuscated package decompiled; CFR
    reported `Exception decompiling` / `Unable to fully structure code`
    on the Main-Class `PLhWEEjyn.main` and its `parseSetupType` and
    `getKey`, and left the string decrypt as unresolved integer-keyed
    `x(a,b)` / `K(a,b)` calls with a large `char[]` cipher table in the
    static initializer. The obfuscator is a **string-encryption +
    control-flow-flattening** pass — CFR handled the ALU but the switch
    dispatchers it emits defeat clean structuring. Progress is real but
    the story is not written yet: decompiling those calls needs an
    evaluator for the two static methods, not a decompiler.

## Controls

- **`peel_launcher.js` never runs the payload.** It writes each stage to
  disk and stops on non-match. Negative control: running it on a random JS
  file yields zero layers and exits.
- **`unpack_installer.sh` writes to a caller-supplied directory.** No path
  above the working directory is touched, and the script refuses to run
  if any of `7zz`, `node`, `npx`, `shasum`, `file` are missing.
- **`.gitignore` blocks every extracted artifact** by extension
  (`*.exe *.dll *.7z *.jar *.zip *.asar` and directories `out/`, `samples/`).
  Negative control: `git status` in a freshly extracted tree shows no
  malware paths as untracked.
- **Hash pinning.** `HASHES.txt` names the sample by SHA-256, so anyone
  re-running the unpack can confirm they are looking at the same bytes.
  A build with a different C2 IP or a different `APP_NAME` will not
  collide.

## Open items

- The 23 decompiled classes in `com.xc17edb19a.*` are not yet readable —
  CFR emits large `switch(int)` dispatchers because the obfuscator flattens
  control flow, and every string is `K(intA, intB)` or `x(intA, intB)`. A
  next step is a small string-decryption harness (either evaluate the two
  static methods against the cipher tables in the static initializer, or
  reimplement them from the bytecode) so that the class files can be read
  as English rather than integers.
- Dynamic behavior is not recorded here because none was run — the C2
  wire format, the actual browser/wallet target list, and the `ShellExec`
  arguments live inside strings that are still integers.
- The `native/*` per-platform binaries inside the JAR (`.so`/`.dll`
  /`.jnilib`/`.a`) were assumed to be stock JNA platform libraries on
  the shape of their names, not verified byte-for-byte.
