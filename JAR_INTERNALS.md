# Inside `emre.jar` — Exastealer v1.0

Reverse of the Java stealer payload that `launcher1.js` extracts and launches.
Complements [`README.md`](README.md) (the delivery chain) and
[`PEYNIR_DLL.md`](PEYNIR_DLL.md) (the native UAC-bypass helper).

The JAR ships **4 539 `.class` files** obfuscated with a custom string-encryption +
control-flow-flattening pass. The obfuscator randomises per-class field and
method names — some classes name their string table `K[]` and their integer
table `x[]`, other classes swap those names. Every method body is flattened
into a `switch(state)` dispatcher with `goto`-style state transitions rather
than plain control flow.

Two decrypt-method variants are used across the package, both keyed by
`getStackTrace()[1]` — the immediate caller's class-name and method-name
hashes are XORed into the mask, so the same ciphertext produces different
plaintext depending on where the call site sits.

**Variant A** (`K(int a, int b)`):
```
idx      = a XOR K_INDEX_MAGIC
caller   = ((callerClass.hashCode() ^ callerMethod.hashCode()) >> 16) ^ CALLER_HASH_MAGIC
for each i in ciphertext K[idx]:
    plaintext[i] = ciphertext[i] XOR (XOR_TABLE[i & 31] XOR (b >> 16) XOR caller)
```

**Variant B** (`K(int a, int b, char c)`):
```
idx      = c XOR K_INDEX_CHAR_MAGIC
caller   = ((callerClass.hashCode() ^ callerMethod.hashCode()) >> 16) ^ CALLER_HASH_MAGIC
for each i in ciphertext K[idx]:
    v = apply_prechain(ciphertext[i])   # sequence of `+ imm` and `^ imm` ops
    plaintext[i] = v XOR caller XOR <one of {a, b}> XOR (<the other> >> 16)
```

The per-class constants (`K_INDEX_MAGIC`, `CALLER_HASH_MAGIC`, the 32-byte
`XOR_TABLE`, the pre-chain, and which int arg is direct/shifted) all appear as
literals inside each class's decrypt-method bytecode.

## How it was peeled

Since running the JAR was off the table, the extraction was static-then-controlled:

1. `javap -c -p` on every class in `com.xc17edb19a.*` — verified **no** `<clinit>`
   does I/O (no `ProcessBuilder`, `Runtime.exec`, `Socket`, `URLConnection`,
   `Files.*`, `loadLibrary`, or `RegistryKey`). One `<clinit>` reads
   `System.getProperty("user.home")` to seed a `STEALTH_BASES` array — that
   contaminates the extracted table with the analyst's home directory on the
   analysis host, which is why the tables dump is not published from this repo.
2. `Vineflower 1.11.1` decompiled the whole package (`--decompile-inner`,
   `--ignore-invalid-bytecode`, brace-normalised) — CFR bailed on the
   flattened switches.
3. Custom Java reflection dumper (`scripts/dump_tables.java`) loads each
   class inside a fresh `URLClassLoader`, triggers `<clinit>`, and reads every
   `private static final String[]` and `int[]` field by name-agnostic type
   probe. Result: 37 classes with static arrays.
4. Custom Python deobfuscator (`scripts/deobfuscate_strings.py`):
   - parses each decompiled `.java` to find the per-class decrypt method
     signatures and extract the six free constants from their bodies;
   - walks brace depth with a comment/string/char-aware tracker to bind every
     call site to its enclosing binary class name (`Outer$Inner$…` for nested
     types, anonymous inner-class counter for `new I() { … }` blocks) and
     enclosing method name (with `<clinit>` for `static { … }`);
   - reimplements `String.hashCode()` and Java 32-bit arithmetic shift, then
     evaluates the per-call-site decrypt for every match.
   - **2 340 of 2 341** call sites substitute cleanly. The one hold-out is
     a third variant of the string decrypt that appears exactly once in
     `SquEZNKwht`.

## Findings

### C2 protocol

The single C2 endpoint (`http://52.249.219.108:3001`, Microsoft Azure) exposes
at least these routes (recovered from decrypted strings):

| method | path | purpose |
|---|---|---|
| `POST` | `/api/validate-tokens` | key + Discord-token validation |
| `POST` | `/api/discord-injection/<KEY>` | Discord IPC / injection callback |
| `POST` | `/api/internal/log` | error-and-progress logging |

Transport is plain HTTP with the operator's build key `PANEL-XSER-YZ76-YFMK`
passed as `KEY`. The JAR also bundles a `discord.com` / `canary.discord.com`
client (real Discord API) to validate stolen tokens with a request to
`GET /api/v10/users/@me` and `/api/v9/users/@me`.

### Class map (obfuscated → intent)

Recovered from decrypted strings and inner-class type names:

| obfuscated class | role |
|---|---|
| `PLhWEEjyn` | Main-Class. Reads `-game` CLI mode, holds `ENCRYPTED_KEY = "PANEL-XSER-YZ76-YFMK"`, calls `JeJJcSSOx.decryptKey`, disables Task Manager via a `wscript.exe //B //Nologo` VBS dropped to `%TEMP%\<uuid>.vbs`, then hands off to the module runners. |
| `TfixYBtWK` | Persistent C2 poller (`TfixYBtWK.start(key)`). Vineflower could not restructure its dispatcher; the transport is HTTP + WebSocket per class-level imports (`okhttp3`, `Apache HttpClient 5`, `java-websocket`). |
| `CsHfiRTnj` + `$User32` | User32 wrapper. Started with the key by the main. Windows enumeration + activity hooks. |
| `JeJJcSSOx` + `$MyCrypt32`, `$NCrypt`, `$NSS`, `$SECItem`, `$DATA_BLOB`, `$MasterKey`, `$ParsedKeyBlob` | Browser credential decryption. DPAPI (`CryptUnprotectData` via JNA), Chromium AES-GCM master-key unwrap, and Firefox NSS (`PK11_CheckUserPassword`, `PK11SDR_Decrypt`) — the class-init loads Firefox's `nss3.dll` on demand. |
| `DmPNptVEeS` + `$SQLite3`, `$Database` | SQLite reader over Chromium's `Login Data`, `Cookies`, `Web Data`. JNA-bound `sqlite3` interface. |
| `MMhwxaxcc` | Wallet / browser catalog — the target tables live here in cleartext, see below. |
| `XkgqXwdrE` | File-grep and package builder. `ALLOWED_EXTENSIONS` (90 entries) filters what to steal from home directories; entries are then packaged for exfil. |
| `LzdpgQyS` + `$ProfileData` | Browser profile enumeration and per-profile stealer. `LzdpgQyS.runExtraction(ZipOutputStream)` is the exit point that packages the loot into the zip forwarded to the C2. |
| `maGBqBEy` | Discord token stealer. `maGBqBEy.getTokens()` walks Discord Leveldb/local storage; `maGBqBEy.killDiscord()` calls `taskkill` before the run so the target files aren't locked. Ships a large in-process JS payload that gets injected into Discord's renderer to wipe storage and force re-auth to capture new tokens on next login. |
| `kvjohfOH` + `$Coin` | Crypto-wallet stealer (paired with `MMhwxaxcc.DESKTOP_WALLETS`). |
| `UCBjYxHzwv` + `$SteamAccount` | Steam session/loginusers.vdf theft. |
| `NjYGKscRL` + anon `$1..$6` | Interceptor pipeline — six anonymous handlers, one per network target (Discord auth, Braintree, Stripe, etc; see `urls: [...]` arrays in the injected JS). |
| `wfveoAPd` | Injector (Discord renderer, browser extension userscript). `wfveoAPd.inject()` is the entry from `PLhWEEjyn.main`. |
| `IvTHdVAG` + `$PEB`, `$PEB_LDR_DATA`, `$RTL_USER_PROCESS_PARAMETERS`, `$UNICODE_STRING`, `$LIST_ENTRY`, `$BIND_OPTS3`, `$GUID`, `$ICMLuaUtil`, `$Ole32`, `$Ntdll`, `$NtdllExt`, `$Kernel32Ext`, `$TOKEN_ELEVATION`, `$X64_CONTEXT`, `$PROCESS_BASIC_INFORMATION` | The **Java-side reimplementation** of the same UACMe method 41 that `peynir.dll` provides natively. Ships `__NATIVE_CHUNKS` (317 chunks) and `__NATIVE_ORDER` (317 ints) — the base64-chunked bytes of `peynir.dll` itself, dropped from JVM memory when the native shim is preferred. |
| `SquEZNKwht` + `$DebugLogger`, `$MyKernel32`, `$MyAdvapi32`, `$Shell32`, `$TOKEN_ELEVATION` | Windows API layer + `%TEMP%\debug.log` logger. |
| `zDvfTOGiK` + `$BrowserConfig` | Per-browser config records (paths, profile dir layout, extension DB filename). Its String array `x[466]` is the largest per-class table in the JAR. |
| `HIdPkdebB`, `nXstjVHu`, `NGyFAKxu`, `WmJoRcgQD`, `SPwtRpLHG`, `aGQJfZBv$WinError` | Utility/error-code classes; `NGyFAKxu.main` is a stand-alone `System.out.println` debug harness left in the build. |

### Target catalog

Recovered verbatim from the cleartext `MMhwxaxcc` / `XkgqXwdrE` arrays:

**Browsers scanned** (`BROWSER_PATHS`, 5):

- `%LOCALAPPDATA%\Google\Chrome\User Data`
- `%LOCALAPPDATA%\Microsoft\Edge\User Data`
- `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- `%APPDATA%\Opera Software\Opera Stable`
- `%APPDATA%\Opera Software\Opera GX Stable`

Recovered from decrypted call sites (superset of the above; each channel has
its own `\Local State`, `\Default`, `\Profile N` derivations, and Brave beta /
nightly, AVAST Browser, etc.):

- Brave Beta / Nightly (`AppData\Local\BraveSoftware\Brave-Browser-Beta`, `-Nightly`)
- AVAST Browser (`AppData\Local\AVAST Software\Browser\User Data`)

**Profile dir names probed** (`PROFILES`): `Default`, `Profile 1` … `Profile 5`,
`Guest Profile` (per decrypted call sites).

**Desktop wallets** (`DESKTOP_WALLETS`, 48 — first 20 shown):

- `AppData\Roaming\Exodus`
- `AppData\Roaming\atomic`
- `AppData\Roaming\Binance`
- `AppData\Roaming\Electrum\wallets`
- `AppData\Local\Coinomi`
- `AppData\Roaming\Guarda`
- `AppData\Roaming\com.liberty.jaxx`  (Jaxx Liberty)
- `AppData\Roaming\Zcash`, `Ethereum`, `Bitcoin`, `Litecoin`, `DashCore`, `Dogecoin`
- `AppData\Roaming\monero`, `Monero`
- `AppData\Roaming\Electrum-LTC`, `ElectrumSV`, `ElectronCash`
- `AppData\Roaming\Armory`
- `AppData\Roaming\Trezor Suite`
- … 28 more.

**Browser wallet extensions** (`EXTENSION_DB`, 61 — Chromium extension IDs
loaded from `<profile>\Local Extension Settings\<id>\`):

- `nkbihfbeogaeaoehlefnkodbefgpgknn` — MetaMask
- `ejbalbakoplchlghecdaalmeeeajnimhm` — Binance Chain Wallet
- `mclnbpgomkibmidocpdlndicnnandncd` — TronLink? (mainstream Web3 wallet)
- `bfnaoomekhelobohpbefokbaekckpjoe` — SafePal / hardware helper
- `hnfanknocfeofbddgcijnmhnfnkdnaad` — MetaMask (legacy)
- `egjidjbpgmcnihkmyhgghhhebgeachob` — Phantom (Solana)
- `ibnejdfjmmkpcnlepejjdphneihoonee`, `ibnejdfjmmkpcnlpebklmnkoeoihofec` — misc EVM wallets
- … 54 more.

**File-grep extensions** (`ALLOWED_EXTENSIONS`, 90):

```
.7z .aac .ai .avi .bat .bmp .c .cfg .cmd .conf .cpp .cr2 .crw .cs .css .csv
.db .dng .doc .docx .eml .epub .flac .gif .gz .htm .html .ics .ini .java
.jpeg .jpg .js .json .jsx .key .log .m4a .mkv .mov .mp3 .mp4 .mpeg .mpg
.msg .nef .odp .ods .odt .ogg .one .ost .pdf .pem .php .png .ppt .pptx
.ps1 .psd .pst .py .rar .raw .rtf .sh .sql .sqlite .svg .tar .tex .tif
.tiff .ts .tsv .tsx .txt .vcf .wallet .wav .wma .wmv .xls .xlsx .xml
.yaml .zip
```

The `.wallet`, `.key`, `.pem`, `.psd`, `.pst`, `.ost`, `.eml`, `.msg`, `.docx`,
`.xlsx`, `.pdf` set is telltale: wallets, private keys, Outlook stores, and
Office documents that likely contain credentials or recovery phrases.

### Anti-analysis

- **Task Manager disable** in `PLhWEEjyn.disableTaskManager`: drops a random
  `%TEMP%\<8-hex>.vbs` (UTF-8), then launches
  `wscript.exe //B //Nologo <path>`. `//B` is silent, `//Nologo` suppresses
  the banner. The VBS itself is a large PowerShell-in-VBS payload (recovered
  from a decrypted string, ~1 KB) that manipulates `DisableTaskMgr` under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`.
- **Discord kill before scrape** (`maGBqBEy.killDiscord`): stops Discord's
  `Discord.exe`/`DiscordCanary.exe`/`DiscordPTB.exe` via `taskkill /F /IM`
  so the Leveldb files are unlocked when the stealer opens them.
- **Discord renderer injection** (`wfveoAPd.inject` + inline JS):
  `webpackChunkdiscord_app.push([[Symbol()], {}, o => { … }])` pushes a fake
  module into Discord's webpack chunk map to hook `token`, session-refresh,
  and payment (Braintree / Stripe) traffic; the payload then triggers a
  reload to `discord.com/login` so the victim re-authenticates and a fresh
  token is captured.
- **HTML lures** (`beta-game-setup.html`, `mc-client-setup.html`,
  `watch-setup.html`, `fake-error.html`) are pre-styled Windows-installer
  lookalike windows. `LFVkhEygta.SetupType` enumerates them:
  `GAME_SETUP`, `MC_CLIENT`, `WATCH`, `FAKE_ERROR`.

### Operator artefacts

- **Panel key**: `PANEL-XSER-YZ76-YFMK` (baked into this build's
  `PLhWEEjyn.ENCRYPTED_KEY`; sent to `/api/validate-tokens` at startup).
- **Setup-mode CLI flag**: `-game` (passed as `--startup` to the launcher, and
  as `-game` to this JAR to enable full stealer mode).
- Language / cultural hint: `APP_NAME = "emre"` (Turkish given name), native
  shim named `peynir` (Turkish "cheese"), unchanged from prior findings.

## Reproducing the deobfuscation

```bash
# Requires: openjdk 21+ (Homebrew's `openjdk` package), Python 3.9+, sevenzip.
scripts/unpack_installer.sh /path/to/ElriaGame.exe out          # → out/jar/*.class
javac scripts/dump_tables.java && \
  java -cp scripts DumpTables out/data/emre.jar out/tables.json  # ~5s, triggers <clinit>s
# Decompile the obfuscated package with Vineflower before running the script
java -jar vineflower-1.11.1.jar out/data/emre.jar out/decomp \
    --decompile-inner=1 --ignore-invalid-bytecode=1
python3 scripts/deobfuscate_strings.py out                        # ~30s, 99.96% success
# out/decomp-decrypted/com/xc17edb19a/*.java now carries the substituted literals.
```

`out/tables.json` is deliberately **not** published: it embeds the analyst's
home-directory path (leaked by `IvTHdVAG.STEALTH_BASES[0]`'s `<clinit>` reading
`user.home`), and it also carries the base64-chunked bytes of `peynir.dll` in
`__NATIVE_CHUNKS`. Run the extractor locally to reproduce.

The full decrypted Java source is likewise not published — it is a working
stealer, and this repo's policy is analysis + tooling, not payload
redistribution.

## Open items

- One 3-arg `x`-named string decrypt in `SquEZNKwht` uses a fourth variant
  I have not modelled; it holds 4 strings I have not read.
- `TfixYBtWK` (the C2 poller) defeated Vineflower's control-flow restructuring
  in one place. Its transport can be recovered by hand from the bytecode —
  the class-level `okhttp3` / `java-websocket` imports are the surface.
- Native `__NATIVE_CHUNKS` reconstruction (base64-decode + reorder by
  `__NATIVE_ORDER` → `peynir.dll`) is confirmed by matching the SHA-256 of the
  reassembled bytes against `peynir.dll` extracted directly from the JAR.
- Whether the CLI flag `-game` gates only the stealer or also gates
  fingerprint-and-idle-out (some builds ship two modes) is not yet answered.
