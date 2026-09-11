# FINAL FANTASY TYPE-0 HD — verified internals (knowledge base)

Consolidated from the reverse-engineering sessions of 2026-08-29 … 2026-09-05. Everything
below was either read byte-exact from the unpacked module image or confirmed by runtime
traces; falsified hypotheses are listed separately so they are not re-investigated.

Addresses are virtual addresses for ImageBase `0x140000000` (RVA = VA − base). All Type-0
HD builds seen so far share them, but always re-verify a signature with `FindOne` before
patching.

---

## 1. Tooling and workflow

- **The exe is SteamStub-encrypted on disk** (`.text` entropy 8.0, entrypoint in `.bind`).
  Two decrypted copies live in `dump/` (gitignored):
  - `dump/fftype0hd.exe.unpacked.exe` — made with **Steamless** (`C:\Tools\Steamless\Steamless.CLI.exe
    dumpftype0hd.exe`, variant 3.1 x64). A clean PE at base `0x140000000` with correct data pointers;
    verified byte-identical to the memory dump at all known code sites (2026-09-06). Preferred input for
    static analysis. Recreate from the Steam exe in one command if lost.
  - `dump/image.bin` — the older runtime memory dump (file offset == RVA; stored data pointers were
    relocated to base `0x7FF7ECD90000`, so `RVA = qword − 0x7FF7ECD90000`). Still what the
    `docs/tools/*.py` scripts read; also contains live `.data` state.
- **Ghidra** (`C:\Tools\ghidra_12.1.3_PUBLIC`, JDK 21 at `C:\Program Files\Eclipse Adoptium`):
  project `C:\Tools\ghidra_projects\FFT0`, program `fftype0hd.exe.unpacked.exe`, fully auto-analysed.
  Decompile without the GUI: `docs/tools/ghidra/decompile.ps1 out.c 0x140371A20 ...` (headless
  post-script `DecompileAt.java`, accepts VAs or RVAs). Use it for big switch-style functions
  (script-command handlers) where capstone listings are too slow to read.
- **Disassembly**: capstone 5, `disasm.py` (pdata-bounded) / `dis_range.py <va> <bytes>`
  (raw). Many functions have no unwind entry: `pdata` chunks are *not* function starts —
  find the real start by walking back to `CC CC` padding. Starting mid-instruction
  desyncs capstone.
- **Injected asm** is assembled at runtime by keystone inside the mod. Always test-assemble
  with keystone first. The mod's `ParametricASMJump` supports `?N` (rip-relative pointer
  cells), `$N` (immediates), `%N` (float cells) and single-letter labels (`A:` … `jmp B`).
  It does **not** accept `jmp qword ptr [rip + ?N]` (runtime `ASM FAIL`, block skipped).
  The replaced region must be ≥ 5 bytes and must end on an instruction boundary — a wrong
  jump-back length crashes on the next area load.
- **Signatures**: check uniqueness in the dump, and check that a later signature does not
  overlap bytes an earlier hook already replaced (the second `FindOne` fails at runtime).
- **Build**: `build/FFT0HD Unlocker.vcxproj`, configuration `Release Win64`, MSBuild from
  VS 18. `source/Utils` (CookiePLMonster/ModUtils submodule) needs two local edits for the
  current MSVC STL (no `stdext::make_checked_array_iterator`, add `<string>`); they are not
  committed — binaries matter, not source buildability.
- **Deploy**: copy the `.asi` into `…\FINAL FANTASY TYPE-0 HD\WIN\`, edit
  `FFT0HD Unlocker.ini` there, read `FFT0HD Unlocker.log` there. The game must be closed
  when copying.
- **Diagnostics compiled into the mod** (all `[Diagnostics]`, default off): `TraceBossPos`
  (+`[BossProf]`, `[BossAI]`, `[Roster]`), `TraceWatchdog` (26 event hooks: state entries,
  leg kills, script opcodes, property/AI-table queries, event bits, RaiseAiEvent, animation
  frames, AI-block clears), `TraceMove` (+`[Party]`, `[Param]`), `WatchAiEvent` (DR0 hardware
  write watch + VEH → logs writer RIPs), `WriteWatch`, `TraceSounds`, `TracePitch`,
  `TierScan`, `FpsToggleKey` (F10 flips the limiter cell; visually did not take effect).
  A hardware write watch is the fastest way to find who writes a cell.

## 2. Global tables and cells

| Address | Meaning |
|---|---|
| `[0x667E20]` | actor channel table; actor = `[tbl + ch*8 + 0x18]`, channels 0..0x41 |
| `[0x658840]` | AI-block table, stride `0x5a8`, channel byte at `+8` |
| `0x658CF4` | channel of the *original leader* — NOT the controlled character (see §7) |
| `0x740598` / `0x74126D` / `0x740940` / `0x655C10` | controlled party slot and its entry table (see §7) |
| `0x658BD8` | walk-toggle tier byte (0/1/2); the mod's L3 rewire toggles 1↔2 |
| `0x611668` | tier multiplier rows, stride 16: `{m1,m2,m3,iconId}` = 1.0 / 1.5 / 2.0 |
| `0x611E8C` | stored m1 |
| `0x636FF0` | current move mode (7 walk / 8 run / 9 sprint) — SHARED across party actors |
| `0x636FF4/8/C` | per-mode base speed for that mode — SHARED |
| `0x637000` | base for `[actor+0x2a8]` — SHARED |
| `0x637004/8/C` | live multipliers m1/m2/m3 |
| `0x638B20/24` | left stick X/Y ints ±255 (right stick `0x638B28/2C`) |
| `0x658F70` | game mode (1 = battle-event/cutscene script running, 3, 9 …) |
| `0x6D1CEC` | referenced only by an upstream patch; **no code touches it in this build** |
| `0x658D30` / `0x658D34` | lock-on target channel (−1 none) / its 150-frame timer |
| `0x612360` | battle-script opcode table, stride `0x30`, handler at `+8` (index > 0xFF exists) |
| `0x1406578F4`, `0x1406579BC`, `0x1406585F0` | AI tick gate bytes (see §5) |

## 3. Actor structure (offsets from the actor pointer)

| Offset | Meaning |
|---|---|
| `+0x12` | mode byte set by SetMode `0x140191ff0` (1..5) |
| `+0x18` | channel (sbyte) |
| `+0x60` | script context; `+0x70..` bitmask of started script slots |
| `+0xdc/e0/e4` | velocity vector |
| `+0x150/154/158` | move direction |
| `+0x160` | translation motion profile (see §4); `+0x164` phase, `+0x168` duration |
| `+0x1a8` | facing/turn profile; `+0x1ac` phase, `+0x1b0` duration, `+0x1d8` its `+0x30` |
| `+0x1f0` | second angular servo (head/body aim), same gains |
| `+0x238` | time-multiplier profile (output divides the translation finite difference) |
| `+0x290` | previous cumulative of the translation profile |
| `+0x298` | current run speed; `+0x29c/+0x2a0/+0x2a4` walk/run/sprint slots; `+0x2a8` = base × m2 (scales scripted moves: dash) |
| `+0x2ac/+0x2b0` | facing-servo gains |
| `+0x2D0 + sbyte[+0x364]*0x38` | mover pointer (see §4); `+0x364` mover index |
| `+0x360` | class word: `0x2019` boss/leader, `0x200B` General Qator Bashtar, `0x2022` ch2 flying unit, `0x2016` soldiers, `0x000A/0005/0007` party members, `0x0000` empty |
| `+0x550` (AI block) | current behaviour id (in the AI block, not the actor) |
| `+0x874` | flags: bit 2 = AI alive/active (tick gate) |
| `+0x884` | motion id word (not reliable for every class) |
| `+0x934` / `+0x938` | HP / max HP (party members ~600, Qator 6015, ch2 flyer 6718) |
| `+0x95c` | flags: bit 0 = "may act" (cleared on kill/knockdown), bit 2, bit 4 |
| `+0x95d` | bit 0x20 = death pending, bit 0x80 = dead |
| `+0x965` | == 1 while in a cutscene (the analog watcher and the L3 handler skip) |
| `+0x9f2` | bit 0 = dead flag (script op 0x114 tests it) |
| `+0xc64` | AI scheduler state: 0 wait, 1 issue, 2 running |
| `+0xc68` | scheduler flags (bit 1 running, bit 4 issued, bit 8) |
| `+0xc6a` / `+0xc6c` | action countdown (word, −1 per **rendered** frame) / reload |
| `+0xc6f` | last attacker channel |
| `+0xccc` | movement dispatcher state (1 walk leg, 2 run leg, 3 turn servo, 4 wait-for-turn) |
| `+0xcd4` | dispatcher flags (0x10 = profile needs rebuild, 0x2 arrival check, 0x8 snap at leg end) |
| `+0xcd6` / `+0xcd8` | leg frame counter (rendered frames) / budget (30-fps frames; 0xFFFF = none) |
| `+0xcfc` | packed type: `(x<<6)>>24` = type; 2 = party/player-controlled, 5 = script-driven enemy |
| `+0xD28` | action queue ring (count `+0xc`, capacity `+4`, head `+8`, entries 0x2c bytes) |

Mover (from `actor+0x2D0+idx*0x38`): `+0x08..0x10` world position, `+0x18..0x20` per-frame
delta, `+0x58..0x60` facing dir, `+0x78` speed, `+0xa8` mode bits (4 active, 2 run with
vertical, 1 position set externally, 8 skip), `+0x488` multiplier (1.0), `+0xa08/+0xa10`
owner actor / event callback. Speed-mover `0x1403C0BC0` writes delta = speed × dir
(Y only when bit 2); integrator `0x1403C0C80` adds it with **no fps scaling**. Upstream's
"characters walking speeds" patch scales X/Z there by 30/fps but **not Y**, and its
cutscene gate reads the dead cell `0x6D1CEC`, so it is always active.

## 4. Motion profiles, movement dispatcher, battle script

- **Profile clock** `0x1401D3F00(profile, mode)`: mode 1 arm at `0x1401D3F46` adds the
  phase step (upstream `CutsceneWalkFix` replaces the 1.0 with 30/fps) and evaluates the
  closed-form trapezoid `0x1401D3890`; terminates when phase ≥ duration. Mode 0 arm
  (`0x1401D3F72`) applies `+0x30` as a per-call velocity with decay (direct-motion
  consumer — this is why a global rescale of `+0x30` broke everything). Nine call sites;
  translation `0x1401B9792` (`+0x160`), facing `0x1401B960F` (`+0x1a8`), time-multiplier
  `0x1401B96AE` (`+0x238`), head servo `0x1401993CF` (`+0x1f0`), five in an unrelated
  angular object `0x1401B0710`.
- **Evaluator** `0x1401B9580`: velocity = (profile output − `+0x290`) / `xmm9`
  (`+0x238` output), then SetSpeed via vtable `+0xE0` and SetMoveDir3D via `+0xC8`.
  Facing output is applied as an absolute angle via vtable `+0x70`.
- **Facing servo** is rebuilt every frame from phase 0 in dispatcher state 3
  (`0x14019ba20`), and only when flag 0x10 is set in state 1 (`0x14019bcc0`). Rebuilding
  from phase 0 with a step h gives `v(n+1) = v·h + 0.5·a·h²` — at h = 0.25 a geometric
  decay (the Commander Schmitz bug). Rule shipped: step 1.0 when entry phase == 0 (servo),
  else 30/fps (scripted turn); enemy class `0x20xx` always 1.0 (`EnemyTurnFullRate`).
- **Dispatcher** `0x14019bfc0` by `[actor+0xccc]`: 1 → `0x14019bcc0`, 2 → `0x14019bbc0`
  (waits `+0x160`==0, optional snap via vtable `+0x40`), 3 → `0x14019ba20`, 4 → waits
  `+0x1a8`==0 then clears state. States 1 and 3 have a **rendered-frame budget watchdog**
  (`cd6 ≥ cd8` kills the leg and zeroes both profiles); it is real but, for every boss
  traced so far, budgets were 0xFFFF and it never fired.
- **Script VM** (one engine for field/event scripts, battle AI scripts and per-actor threads;
  decompiled 2026-09-07, see §4a). `0x140370C70` is the command ARGUMENT PARSER (called once per
  new command, not per tick). Thread record (stride `0x510`, call stack frames of `0xa0` at `+8`,
  frame count at `+0x508`): opcode `+0x24` (−1 = none pending), PC `+0x28`, end PC `+0x14`,
  owner channel `+0x34`, args `+0x38..`, result `+0x30`, waiting flag `+0x2c`, finished `+0x2d`,
  paused `+0x2e`. The VM TICKS EVERY RENDERED FRAME (not 30 Hz); commands only *appear* to run at
  30 Hz because the wait opcodes are stretched by upstream's per-address dedup patches. Useful ops: `0x09` wait N ticks; `0x60/0x6F` call label; `0x114` "actor
  dead?"; `0x122` actor property getter `0x1401A2080`; `0x153` AI-table target metric
  (`0x140275340` picks the nearest target; sub 2 = distance bucket); `0x15F` event-bit
  test (arg0 selects word: 0 → `aib+0x1ac`, 1 → `+0x1a0`, 2 → `+0x1a8`; arg1 = bit);
  `0xD2/0xD5/0x3B/0x3C` scripted walk/run legs (frame budget from `float[rec+0x3c]`);
  `0xD7` turn to face; `0x15/0x16` SetActorParam.
- **Run builder** `0x14019B530` (state 2 trapezoid), walk setter `0x14019B8E0` (state 1),
  turn setter `0x14019B480` (state 3, budget 8 frames). Their callers are the ops above.

### 4a. Script VM internals (decompiled with Ghidra, 2026-09-07)
- Tick drivers: `0x140376f70` (per-frame game-system update) runs the GLOBAL VM `[sys+8]` via
  `0x14037f2a0(vm)` and then the field manager `0x1403816b0`, which runs the FIELD VM `[fm+0x18]`
  the same way and then updates the 3 party actors (vtable `+0x28`). Both start a `"main"` thread
  when none is active (`0x14037f620`). Per-actor script threads run through `0x140371630` from
  actor code (`0x1401b5f22`, `0x1401bb4b9`). Third caller of the tick: `0x14034c4e7` (battle side).
- `0x14037f2a0` loops over threads `[vm+0]` × `0x510` and runs each until it blocks: step
  `0x140371390` decodes one instruction by the low nibble of the first word: 1 → control flow
  `0x140371140` (case 6 = if/else chain, 7 = jump, 0xc = loop, 0xd = end), 2 → engine command
  (parse args `0x140370c70`, handler from table `PTR_140612368[opcode*6]`, completion check
  `0x140370a60`; the thread yields while the command is pending), 8 → script function call
  `0x140371000` → `0x14037f120`, else → expression `0x1403721c0`.
- Expression evaluator `0x1403721c0`: RPN over a 32-entry stack at `0x14065aeb0` (12 bytes: type,
  kind, value). Operand types: 4 = constant from the script's pool `[script+0x150]`, 5 = small
  immediate / VARIABLE REFERENCE (`kind = bits 4-5`, index = `word>>6`), 6 = operator
  (`op = word>>4`), 2 = nested engine command, 8 = function call. Operators go to
  `0x140371a20(rec, op, &a, &b, intMode)`: 0x10 add (Banz99's "case 16"), 0x11 sub, 0x0d mul,
  0x0e/0x0f div, 0x12/0x13/0x6b/0x6c compares, 0x6d/0x6e equality with ±1.19e-7 tolerance
  ("case 110"), 0x17 assign, **0x69 `var++` ("case 105"), 0x6a `var--`, 0x71 `var += x`,
  0x72 `var -= x`**. Variable reads: `0x140372150`.
- THREE variable stores, selected by `kind`: 0 → `float[[rec+8] + idx*4]` (script-object
  variables), 1 → `float[[rec+0x80] + idx*4]` (per-context block allocated at call time,
  `0x14037f120`, zero-filled), 2 → `float[rec+0x5c + idx*4]` (thread locals = the up-to-8 call
  arguments). Increment sites: store 0 `0x140371f78`, store 1 `0x140371fb2`, store 2
  `0x140371fea`; decrement: store 0/1 shared `0x14037203c`, store 2 `0x140372070`.
- Upstream ("Gameplay fixes #1/#2") deduplicates ONLY the store-0 sites, and only while the
  value is in [1,10) (or when a caller stack slot `[rsp+0x60]` equals `0x140574CA0`); values ≥ 10
  always advance. `[rsp+0x10]` at that site is the variable's value left by `0x140372150`. Its asm
  also clobbered r13/r15, which the evaluator keeps its thread index and flag in — a `++` inside a
  longer expression corrupted them. Fixed in the fork (volatile r8/r9/r11, same logic).
- **A plain per-address "once per 30 Hz frame" dedup HANGS THE GAME AT BOOT**: scripts loop
  `x++` inside a single tick (`while (x < N) x++`), so the counter never reaches N (2026-09-09,
  reproduced: CPU spin, log stops after init). That is why upstream limited its dedup to small values.
- **Plateau dedup (advance once per 30 Hz frame, allow in-frame repeats) MAKES EQUALITY EVENTS FIRE
  4x**: the field script triggers dialogue lines with `if (v0[14] == 30)`; a value held for 4 rendered
  frames fires the line 4 times (2026-09-10, ch3 m2 dialogue repeated).
- **Fractional stepping (+30/fps per rendered frame, loop repair on the 2nd in-frame touch) BREAKS
  DESCENDING LOOPS**: `i--` gives 6.75, truncation makes index 7 vanish; enemy AI target loops that
  count down never see the player → some enemies never attack (2026-09-10).
- **Gating the whole script VM to 30 Hz (`ScriptTick30Hz`) breaks engine interactions** that expect
  the script every frame (phantoma harvest prompt after a kill: prompt missing, character jitters as
  if a button were held). Kept as an off-by-default experiment only.
- **Shipped scheme (`ScriptVarDedupAll`, default 1, all 5 `++/--` sites, 2026-09-10)**: list of 32
  entries {addr, rendered frame, 30 Hz frame, accumulated nudge}; first touch of an address in a NEW
  30 Hz frame: subtract the accumulated nudge and step by a whole ±1 (value is an exact integer at
  every tick boundary, like the original); repeat touch in the SAME rendered frame: whole ±1 (in-tick
  loops exact, up and down); touch in a LATER rendered frame of the same 30 Hz frame: ±1/64 nudge in
  the direction of the value's sign (equality against integers is true for exactly one frame per
  tick, truncation toward zero is unchanged). Frame counters come from upstream's per-frame setup
  hook. Verified: ch3 mission 2 start, dialogue once, enemies attack, phantoma prompt, the pilot
  spawn at the mission end, 65-minute session, no hang. Stats ratio whole:nudge ≈ 1:3 at 120 fps.
  A first version had the 30 Hz-frame branch inverted (nudge instead of landing) → scripts 16x slow.
- **Script file format** ("ATELY", decoded 2026-09-09, tool `docs/tools/scriptdis.py`): object header
  fields `+0x118` code, `+0x120` fn table, `+0x138/+0x140` label tables, `+0x148` labels (`0xFF0000nn`,
  offset pairs), `+0x150` float constant pool. Code: 0x30-byte file header, then functions =
  8-byte header `{fn id, body length}` (4-byte aligned) + body; the last ring PC of a command is
  recorded 6 bytes after the command start. Statement word low nibble: 1 control (op=(w>>4)&0xF:
  1/2/A `if (expr) skip next 4 bytes` — the next statement is usually `GOTO label`; 4 goto label w1;
  5 label w1; 6 switch(expr) block w1; 7 case(expr) (falls through as a statement); 8 endswitch;
  3 else-mark; C return expr; D end), 2 command (`id<<4|2`, w1 flags/result target, w2 arg bytes),
  8 call (`fnid<<4|8`, 10-byte header + args), 3 expression statement (len = w>>4). Expression
  operands: 4 const[w>>6], 5 variable (kind=(w>>4)&3: 0 script-object vars, 1 context block, 2 call
  args; idx=w>>6), 6 operator (0x10 + 0x11 - 0x0d * 0x0e / 0x12 < 0x13 > 0x6b <= 0x6c >= 0x6d == 0x6e !=
  0x6f AND 0x70 OR 0x17 = 0x69 ++ 0x6a -- 0x71 += 0x72 -=), 2 nested command, 8 nested call.
  Script commands seen: id 0x29E SetActorVar(idx,val), 0x29F GetActorVar(idx) (`actor+0x90+idx*4`,
  16 floats, -1 = unset), 0x8E DistanceToPoint(x,z), 0x0A wait, 0x128/0xF/0x52/0xC state
  enter/leave wrappers, 0x4C SetFlag(n,v).
- **Diagnostics added 2026-09-09**: `[Diagnostics] HangWatch` (default 1; stall report after 8 s
  without rendered frames, or F7: thread RIPs + stacks, evaluator state, script rings, per-channel
  script dumps `<ini>_script_*.bin`), `TraceScriptOps` (default 1; ring of the last 512 commands and
  a spin-filtered ring of the last 512 distinct-PC commands), `WatchActorVar = ch,idx` (DR0 write
  watch on an actor variable). Tools: `docs/tools/scriptdis.py`, `calls_to.py`.
- Unresolved: Banz99's "global counter increasing by 1 each game cycle" that event scripts compare
  against (ship-jump enemies at frames 210/225 in his save) — not yet located; may be a store-1/2
  script counter (now deduped) or an engine command result.

### Lock-on camera (verified 2026-09-05)
- Camera update function `0x1402f1ef0`; lock-on branch runs when `[0x658f48] == 4`. The stock code has
  NO smoothing: each frame it computes the yaw error to the target and applies it fully (instant snap),
  which is why the camera whips when an enemy circles the player.
- Patched site `0x1402f278a` (signature `F3 0F 10 4C 24 30 41 0F 28 C1 41 0F 47 C0 F3 41 0F 58 CC`,
  19 bytes): error `e` (xmm1) becomes `sign(e) * max(|e| - dead, 0) * gain`, with `dead` in radians and
  `gain = 1 - (1 - p)^(30/fps)` recomputed by the camera watcher so the feel is fps-independent
  (`p = LockFollowPercent/100`, `p >= 1` → gain 1 = stock).
- Tuner window: the host exe has no comctl v6 manifest, so `TOOLINFOW.cbSize` must be `TTTOOLINFOW_V2_SIZE`
  or `TTM_ADDTOOL` fails silently (no tooltips). Fixed in 0.5.4.

## 5. Enemy AI scheduler and events

- **Tick** `0x140194A16`: gates = `[0x1406578F4]!=0`, game state, `[0x1406579BC]==0`,
  type 2..5, predicate `0x140026B20` (`[95c]&1 && !([9b7]&2) && [a09]==0 && [a17]==0`),
  `[0x874]&2`. State 0 decrements `+0xc6a` once per **rendered frame** (`0x140194BED`);
  0 → state 1 → issue (type 5 = start script slot via `0x1401BB5C0`; types 2–4 via
  `0x1402744F0/0x140266010`). `AiCountdownFix` steps the countdown every k-th AI frame,
  k = round(fps/30), counted at the AI begin-frame loop `0x140263B9C`.
- **AI block** (stride `0x5a8`): `+0x48` flags, `+0x170..+0x1b0` event words,
  `+0x1a0/+0x1a8/+0x1ac` event bits the scripts poll, `+0x1b4` keep flag, `+0x508..`
  per-target table (words `+0x50a/+0x50c/+0x50e`, stride 8), `+0x550` behaviour id.
- **Events**: the only setter is `RaiseAiEvent 0x140265750(channel, kind, bit)` (kind 4 →
  `+0x1a0`, 5 → `+0x1a8`). It is reached from the **animation event-track player**
  `0x1403BD780` (via the mover callback `[mover+0xa10]` = `0x1401B4190`): keyframe events
  `{kind, bit, startFrame, endFrame}` fire while the clip's integer frame is inside the
  window. So "attack now" / "clip finished, act" are animation keyframes.
- **Begin-frame clear** `0x14027CAF0` zeroes the event words **every rendered frame**
  (unless `+0x1b4`). Per-frame order at 120 fps: raise → [script poll only on a 30 Hz tick
  frame] → clear. A one-frame event raised between ticks is lost. `AiEventKeepFix` zeroes
  only when the VM runner counter moved since the block's last zeroing.
- **Animation player** (layers of `0xd8` bytes, 5 per actor, updated by `0x1403BFD70`):
  frame 24.8 at `+0x6c`, last processed `+0x70`, rate `+0x74` (the mod sets 29.9/fps),
  length `+0x7c`, flags `+0x84` (bit 0 playing, bit 2 finished, bit 8 loop). Step
  `0x1403BDB60`: `frame += (int)(rate·256)`; non-loop finishes when frame > (len−1)·256
  and clamps. At 30 fps the last frame is dispatched twice, at 120 once.
- **Damage**: `ApplyHit 0x1401969B0(victim, flags, attackerCh, hitInfo)` →
  `TakeDamage 0x140198560`. Kill path: boss classes always take the "death pending" branch
  (`0x1401987FB`: clears `95c` bit 0, sets `95d` 0x20/0x80). Forced knockdown =
  flags 0x180 via `0x140198F80`. Party hits on a flyer use flags 0xF7.

## 6. Movement speed / tiers / analog mode

- **Applier** `0x14019C960(actor, m1, m2, m3)`: writes globals `0x637004/8/C`,
  `[actor+0x2a8] = [0x637000]·m2`, and `[actor+0x298]` = `const[mode]·m1` into the slot of
  the current mode **only if `[0x636FF0]` is 7..9**; otherwise it updates the globals and
  returns (the "global says applied, actor not updated" trap).
- **SetActorParam** `0x14019C620(actor, param 1..0x12, value)` and the script-op handler's
  inline copies at `0x14035CF2D` set the walk/run/sprint slots (7/8/9) and, for any type-2
  actor, publish mode + base to the shared globals and multiply by m1. Party members'
  scripts (PC `0x822A`) set run = 26 or 31.2 and sprint = 26 per character; the game also
  changes them by terrain/state (15.6 / 18.7 / 28.6 / 35.8 seen). `AnalogGlobalsFix`
  publishes only for the controlled channel (7 sites).
- **Native L3 handler** `0x140273D10`: finds the controlled actor (see §7), cycles
  `[0x658BD8]`, applies the row. The mod rewires it into a 1↔2 cap toggle.
- Pad stick gate is not circular: full tilt reads 94–99 % on the axes but ~85 % on diagonals
  (`LS 241..252,0` vs `175,127`). `StickSaturationPercent` (default 85) treats ≥ 85 % as full.
- **Analog watcher** (`StartAutoTierWatcher`, 16 ms): m1 = lerp by (saturated) stick magnitude, m2/m3
  = cap row (`DashAtCap`), re-applies when the global m1 or the actor's live `+0x298`
  deviates from `const[mode]·m1`, skips outside modes 7..9 and in cutscenes.

## 7. Controlled character lookup (do not use `0x658CF4`)

`slot = ([0x74126D] || [0x740940]) ? [0x740598] : 0; entry = [0x655C10 + slot*8];
channel = sbyte[entry+1]; actor = channelTable[channel]`. `0x658CF4` keeps the original
leader's channel across in-field switches (traced: the controlled actor moved on channels
1 and 2 while `CF4` stayed 0). Same lookup is used by the action-decide function
`0x140193DD4` and the L3 handler.

### Leads from Banz99 (Discord, 2026-09-06) — script-event frame counters, UNRESOLVED
- Main script-command handler `0x140371140`; commands whose low nibble is 6 are routed to `0x140371A20`,
  and that is where the frame-dependent event timing lives (floating-point counters).
- His attempts, all failed: (a) scale the `+1.0f` side (case 105) like the PSP cheat — only 0.5/0.25
  steps avoid float drift, and events became MORE frame dependent; (b) case 110 = global counter +1 per
  game cycle that events are compared against, multiplied by fps/30 — broke other places; (c) increment
  case-105 counters only once per game cycle — broke one-frame events that fire without a recheck.
- Concrete repro he shipped (save `TYPE0DAT.zip`, keep in `dump/`): after a black-screen transition two
  enemies jump from the ship at frames 210 and 225; those totals are built by increments (e.g. 90+120)
  through `06 01` parts = case 16 in `0x140371A20`. At 90 fps the scene misbehaves (his videos).
- He considers our 0.5.x fixes limited to enemy behaviour; the script-counter problem is the root of the
  ch3 / ch5 softlocks and event overlap. Also: use atom0s/Steamless to unpack the exe instead of a memory dump.

## 8. Known frame-rate dependency patterns (checklist for new bugs)

1. **Per-rendered-frame counters** authored for 30 Hz: AI countdown `+0xc6a`, leg budgets
   `cd6/cd8`, script op `0x179` layer wait, upstream-patched "various timings".
2. **Shared mode-1 profile clock step**: scaling it scales servos too.
3. **One-frame events vs 30 Hz consumers**: anything cleared per frame and polled per tick.
4. **Animation last-frame semantics**: rate 0.249 skips over the last integer frame.
5. **Vertical mover delta unscaled** in upstream's speed patch (minor, `BossVerticalFix`).
6. Party hit frequency and projectile reach on flying targets differ at 120 (unexplained,
   not currently a visible problem).

## 9. Falsified hypotheses (do not repeat)

- WorldMap region `0x140440000..0x140480000` classes never run in field battles.
- The `cd6/cd8` budget watchdog is real but did not cause either chapter-2 boss bug.
- The `+0x30` "velocity unit" rescale on the shared evaluator breaks all movement.
- Lock-on (R1) does not touch the target actor and did not cause the Qator freeze.
- Save-file play-time counter is NOT frame-counted: 40 wall-clock minutes at 120 fps = +40 min in the save (2026-09-05). The Reddit claim that the moogle play-time reward comes 2-4x early is unfounded on this build.
- The 604-point gauge on channel 13 and the "death in the air" belonged to the chapter-2
  flying unit of the first area, not to Qator (channel 6, class `0x200B`).
- Qator's freeze was not the turn-wait alone (`EnemyTurnFullRate` fixed only the first
  stall), nor the animation last-frame dwell (`AnimLastFrameFix`, asm rejected anyway): it
  was the event-clear vs 30 Hz tick race (`AiEventKeepFix`).
- Analog speed drops were not the applier's mode trap alone and not party-global pollution
  alone: the decisive part was the wrong controlled-character cell (§7).
- Kill/Break Sight windows are real-time-correct at 60/120 fps (measured by sound bursts).
- Combat A/B with the mod (same area, 30 vs 120 fps, 2026-09-05): damage per hit identical (183 vs 184),
  Kill Sight window 1.00 s both (30 vs 118 sound requests), hits taken 6 vs 3 — no evidence that 120 fps
  makes fights harder. Perceived difficulty = the game's accuracy/RNG. (`TraceCombat` + `TraceSounds`.)
- The end-of-chapter-1 voice cutoff happens at vanilla 30 fps too.

## 10. Fixes shipped in this fork (post-0.5)

| Version | Switch (`[Movement]` unless noted) | What |
|---|---|---|
| 0.5.1 | `TurnPhaseFullRate` | Commander Schmitz stair entrance: servo at full rate |
| 0.5.2 | `AiEventKeepFix`, `EnemyTurnFullRate` | General Qator Bashtar freeze |
| 0.5.3 | `AnalogGlobalsFix`, controlled-character lookup, `DashAtCap`, `AiCountdownFix` | analog movement after character switches, dash speed, enemy decision pacing |
| 0.5.5 | `ScriptVarDedupAll` (default 1), `ScriptTick30Hz` (default 0), `[OverrideRes] AllowUnsupportedRes` | frame-aware script `++/--` dedup on all stores (chapter 3 mission 2 hang); resolution fallback; HangWatch/TraceScriptOps diagnostics |
| 0.5.6 | `ScriptVarDedupAll` (whole step + 1/64 nudge scheme) | 0.5.5 dialogue 4x repeat, idle enemies; script counters exact at tick boundaries |
| 0.5.4 | `[Camera] LockFollowPercent`, `LockDeadZoneDegrees`; `[Movement] StickSaturationPercent` | lock-on camera soft follow + dead zone; diagonal stick saturation; tuner window regrouped, tooltips fixed |
| — | `AnimLastFrameFix` (default 0) | superseded; its asm form is rejected at runtime |
| — | `BossFixPace/Nav/Turn/Profile`, `ProfileVelocityFix`, `BossVerticalFix` (default 0) | dead or superseded experiments |
