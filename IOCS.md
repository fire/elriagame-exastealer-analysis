# Indicators of compromise — Exastealer / "ElriaGame"

## Network

| kind | value | notes |
|---|---|---|
| C2 (HTTP) | `http://52.249.219.108:3001` | plain HTTP, nonstandard port; ASN/geolocation not checked here |
| C2 route  | `POST /api/validate-tokens`             | key + Discord-token validation |
| C2 route  | `POST /api/discord-injection/<KEY>`     | Discord-renderer IPC / injection callback |
| C2 route  | `POST /api/internal/log`                | progress / error logging |
| Live Discord API | `GET https://discord.com/api/v10/users/@me` | validate stolen token |
| Live Discord API | `GET https://canary.discord.com/api/v9/users/@me` | validate canary token |
| Build key | `PANEL-XSER-YZ76-YFMK` | value of `PLhWEEjyn.ENCRYPTED_KEY` in this build; passed as `<KEY>` path segment and to `/api/validate-tokens` |

The JAR bundles `okhttp3`, Apache HttpClient 5, and `java-websocket`, so
subsequent exfil channels may include WebSocket (`ws://52.249.219.108:3001/...`)
as well as HTTP POST.

## Host

### Filesystem

| path | purpose |
|---|---|
| `%LOCALAPPDATA%\emre\` | install root |
| `%LOCALAPPDATA%\emre\emre.jar` | Exastealer payload |
| `%LOCALAPPDATA%\emre\jre\bin\java.exe` | private JRE (`javaw.exe` preferred) |
| `%LOCALAPPDATA%\emre\data_helper.exe` | renamed copy of `7za.exe` |
| `%LOCALAPPDATA%\emre\data.7z` | staged, deleted after successful extract |
| `%LOCALAPPDATA%\emre\jre.zip` | staged, deleted after successful extract |
| `%TEMP%\launcher_debug.log` | dropper log — appended, never deleted |
| `%TEMP%\debug.log` | JAR-side liveness marker (touched by `emre.jar`) |
| `%TEMP%\.startup_mode` | marker file, opts the next launch into `--startup` mode |

### Registry

| key | value | data |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `emre` | `"…\jre\bin\javaw.exe" -jar "…\emre\emre.jar" --startup` |

### Processes

- `javaw.exe -jar %LOCALAPPDATA%\emre\emre.jar` — child, `windowsHide:true`,
  detached, `cwd = %LOCALAPPDATA%\emre`.
- `ElriaGame.exe` — the Electron shell, self-respawns hidden with
  `_HIDDEN_MARKER=1` and up to `_RESTART_COUNT=2`.

### Environment variables (set by the dropper on its children)

| name | values |
|---|---|
| `_HIDDEN_MARKER` | `"1"` — set on the second (hidden) instance |
| `_RESTART_COUNT` | `"0"`, `"1"`, `"2"` — restart depth |

## File hashes

See [`HASHES.txt`](HASHES.txt).

## UAC bypass (see [`PEYNIR_DLL.md`](PEYNIR_DLL.md))

- CLSID: `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (CMSTPLUA), and IID
  `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` (`ICMLuaUtil`). Both are
  XOR-assembled at runtime from three 16-byte blobs at
  `.rdata:0x180018b80`, `0x180018b90`, `0x180018bb0` in `peynir.dll`.
- Moniker prefix `Elevation:Administrator!new:` is cleartext at
  `.rdata:0x180018b40`; the assembled moniker is
  `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`.
- Method: PEB `CurrentDirectory` / `DllPath` and the loader entry's
  `FullDllName` all rewritten to point at `C:\Windows\System32\`, then
  `CoGetObject(<moniker>, &BIND_OPTS3, &IID_ICMLuaUtil, &ppv)`, then a
  vtable-slot call at `+0x48` on the returned interface (`ShellExec` per
  public docs of `ICMLuaUtil`).

## Detection ideas

- HKCU Run value `emre` whose data ends in `emre.jar --startup`.
- `javaw.exe` whose parent is an Electron app in `%LOCALAPPDATA%\emre\`.
- Outbound HTTP or WebSocket to `52.249.219.108:3001`.
- Elevated `ICMLuaUtil` COM instantiation whose parent is a medium-integrity
  `javaw.exe` under `%LOCALAPPDATA%\emre\`.
- Process whose PEB `CurrentDirectory` reads `C:\Windows\System32\` while its
  image path is under `%LOCALAPPDATA%` — the bypass leaves the spoof in place
  after the elevated call returns.
- Process command line containing `_HIDDEN_MARKER=1` combined with an EXE under
  `%LOCALAPPDATA%\emre`.
- Any signed-looking installer that drops a password-protected `data.7z`
  alongside a bundled `7za.exe` and an Electron shell — the pattern generalizes
  beyond this one sample.
