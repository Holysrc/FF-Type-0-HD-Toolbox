# FF Type-0 HD Toolbox — session notes for Claude

This is a C++ `.asi` mod (fork of Banz99's FFT0HD Unlocker) for FINAL FANTASY TYPE-0 HD.
All patches live in `source/Patch.cpp`. Released at https://github.com/Holysrc/FF-Type-0-HD-Toolbox.

## Read first
- `docs/GAME_INTERNALS.md` — the consolidated, verified knowledge base: tooling, global cells,
  actor/mover/AI-block layouts, motion profiles, battle-script VM, AI scheduler and events,
  animation player, speed/tier/analog system, the controlled-character lookup, a checklist of
  frame-rate dependency patterns, and the list of FALSIFIED hypotheses. Do not re-derive any of
  it from scratch; extend it (and commit) when a new fact is verified.

## Workflow the user expects
- Build: `"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
  "build/FFT0HD Unlocker.vcxproj" -p:Configuration="Release Win64" -p:Platform=x64 -m -v:minimal -nologo`
  (find MSBuild via `vswhere` if the path differs). Output: `build/bin/Win64/Release/FFT0HD Unlocker.asi`.
  `source/Utils` (submodule) needs two local MSVC-compat edits (no `stdext::make_checked_array_iterator`,
  add `<string>`); they are intentionally not committed.
- Deploy directly to the TEST PC over the LAN: `\\192.168.1.214\FINAL FANTASY TYPE-0 HD\WIN\` (host ALIEN; use the IP,
  the name resolves to Tailscale and SMB fails; use the PowerShell tool for UNC paths). Copy the `.asi` there,
  edit `FFT0HD Unlocker.ini` there, read `FFT0HD Unlocker.log` there. The game must be closed while copying.
  Fallback local install: `C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY TYPE-0 HD\WIN\`.
  Do not send the build as a file; the user only launches the game and says when a run is done.
- Verify an `.asi` deploy by md5 and by the log's init lines (`ASM FAIL` / `MISS` / `ABORTED` = a hook did not apply).
- Releases: `Release.zip` = `.asi` + template `FFT0HD Unlocker.ini` + `d3d11.dll` + `keystone.dll`
  (take the last two from any previous GitHub release asset). Tag `X.Y.Z`, `gh release create` with English
  notes in the style of 0.5.1–0.5.3. Commits end with the Co-Authored-By trailer; no session links are ever added.
- Talk to the user in Russian; keep reports short and data-driven (numbers from the log, not impressions).

## Reverse-engineering setup on a new machine
- The exe is SteamStub-encrypted on disk; work from a runtime dump `dump/image.bin` (gitignored — copy it
  over manually from the previous machine, or take a fresh full-module dump of `fftype0hd.exe` at
  ImageBase 0x140000000; file offset == RVA). Tools in `docs/tools/` find it there or via `FFT0_DUMP`.
- `pip install capstone keystone-engine`. Always keystone-check injected asm; the mod's assembler rejects
  `jmp qword ptr [rip+?N]`. Replaced regions must be >= 5 bytes and end on an instruction boundary.

## Diagnostics built into the mod
`[Diagnostics]` keys (default off): `TraceBossPos`, `TraceWatchdog`, `TraceMove`, `WatchAiEvent` (hardware
write watch), `WriteWatch`, `TraceSounds`, `TracePitch`, `TierScan`, `FpsToggleKey`. See GAME_INTERNALS §1.

## Open topics (as of 2026-09-05)
- Chapter 3 softlock at 60 fps (GitHub issue #12), high-fps character steering wobble (upstream-known),
  narrow-corridor camera clipping at distance -150, shadow quality, save-stone flicker.
