# Indicators of compromise — Exastealer / "ElriaGame"

## Network

| kind | value | notes |
|---|---|---|
| C2 (HTTP) | `http://52.249.219.108:3001` | Microsoft Azure, plain HTTP, nonstandard port. Only non-library URL in the JAR. |

The JAR bundles `okhttp3`, Apache HttpClient 5, and `java-websocket`, so
subsequent exfil channels may be WebSocket (`ws://52.249.219.108:3001/...`) as
well as HTTP POST.

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

## Detection ideas

- HKCU Run value `emre` whose data ends in `emre.jar --startup`.
- `javaw.exe` whose parent is an Electron app in `%LOCALAPPDATA%\emre\`.
- Outbound HTTP or WebSocket to `52.249.219.108:3001`.
- Process command line containing `_HIDDEN_MARKER=1` combined with an EXE under
  `%LOCALAPPDATA%\emre`.
- Any signed-looking installer that drops a password-protected `data.7z`
  alongside a bundled `7za.exe` and an Electron shell — the pattern generalizes
  beyond this one sample.
