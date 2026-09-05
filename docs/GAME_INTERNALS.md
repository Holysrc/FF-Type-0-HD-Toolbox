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
  Signatures exist only in memory. Static analysis uses a runtime dump:
  `scratchpad/image.bin` (~11 MB, file offset == RVA; stored data pointers were relocated
  to base `0x7FF7ECD90000`, so `RVA = qword − 0x7FF7ECD90000`). If the dump is lost,
  ask the user for a fresh one.
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
- **Battle script VM**: dispatcher `0x140370C70`, thread record (stride `0x510`): opcode
  `+0x24`, PC `+0x28`, owner channel `+0x34`, args `+0x38..`, result `+0x30`. Threads run
  at **30 Hz**. Useful ops: `0x09` wait N ticks; `0x60/0x6F` call label; `0x114` "actor
  dead?"; `0x122` actor property getter `0x1401A2080`; `0x153` AI-table target metric
  (`0x140275340` picks the nearest target; sub 2 = distance bucket); `0x15F` event-bit
  test (arg0 selects word: 0 → `aib+0x1ac`, 1 → `+0x1a0`, 2 → `+0x1a8`; arg1 = bit);
  `0xD2/0xD5/0x3B/0x3C` scripted walk/run legs (frame budget from `float[rec+0x3c]`);
  `0xD7` turn to face; `0x15/0x16` SetActorParam.
- **Run builder** `0x14019B530` (state 2 trapezoid), walk setter `0x14019B8E0` (state 1),
  turn setter `0x14019B480` (state 3, budget 8 frames). Their callers are the ops above.

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
- **Analog watcher** (`StartAutoTierWatcher`, 16 ms): m1 = lerp by stick magnitude, m2/m3
  = cap row (`DashAtCap`), re-applies when the global m1 or the actor's live `+0x298`
  deviates from `const[mode]·m1`, skips outside modes 7..9 and in cutscenes.

## 7. Controlled character lookup (do not use `0x658CF4`)

`slot = ([0x74126D] || [0x740940]) ? [0x740598] : 0; entry = [0x655C10 + slot*8];
channel = sbyte[entry+1]; actor = channelTable[channel]`. `0x658CF4` keeps the original
leader's channel across in-field switches (traced: the controlled actor moved on channels
1 and 2 while `CF4` stayed 0). Same lookup is used by the action-decide function
`0x140193DD4` and the L3 handler.

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
- The 604-point gauge on channel 13 and the "death in the air" belonged to the chapter-2
  flying unit of the first area, not to Qator (channel 6, class `0x200B`).
- Qator's freeze was not the turn-wait alone (`EnemyTurnFullRate` fixed only the first
  stall), nor the animation last-frame dwell (`AnimLastFrameFix`, asm rejected anyway): it
  was the event-clear vs 30 Hz tick race (`AiEventKeepFix`).
- Analog speed drops were not the applier's mode trap alone and not party-global pollution
  alone: the decisive part was the wrong controlled-character cell (§7).
- Kill/Break Sight windows are real-time-correct at 60/120 fps (measured by sound bursts).
- The end-of-chapter-1 voice cutoff happens at vanilla 30 fps too.

## 10. Fixes shipped in this fork (post-0.5)

| Version | Switch (`[Movement]` unless noted) | What |
|---|---|---|
| 0.5.1 | `TurnPhaseFullRate` | Commander Schmitz stair entrance: servo at full rate |
| 0.5.2 | `AiEventKeepFix`, `EnemyTurnFullRate` | General Qator Bashtar freeze |
| 0.5.3 | `AnalogGlobalsFix`, controlled-character lookup, `DashAtCap`, `AiCountdownFix` | analog movement after character switches, dash speed, enemy decision pacing |
| — | `AnimLastFrameFix` (default 0) | superseded; its asm form is rejected at runtime |
| — | `BossFixPace/Nav/Turn/Profile`, `ProfileVelocityFix`, `BossVerticalFix` (default 0) | dead or superseded experiments |
