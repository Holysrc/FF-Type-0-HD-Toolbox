# FINAL FANTASY TYPE-0 HD — verified internals (knowledge base)

Latest session/release state: [2026-09-20 handoff](SESSION_HANDOFF_2026-09-20.md).
This records cutscene validation limits, the deferred death overlay, release
artifacts and the user's requirement to retain per-setting INI explanations.

Consolidated from the reverse-engineering sessions of 2026-08-29 … 2026-09-17. Everything
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
- **Field cross-references**: `docs/tools/find_field_refs.py 0x6b9 0xce4` lists every
  instruction in the dump that accesses `[reg+disp]` for those displacements (walks `.pdata`
  ranges with capstone). This is how an actor field's readers/writers are found without the
  Ghidra GUI; feed the containing function starts to `decompile.ps1`.
- **`ParametricASMJump(asm, match, matchoffset, jumpback)`**: the hook jmp is written at
  `match+matchoffset`; execution resumes at `match+jumpback` — an ABSOLUTE offset inside the
  signature, NOT a length. `(m, 3, 10)` replaces bytes 3..9 and resumes at 10; if the intended
  region was 10 bytes long, pass 13. Getting this wrong resumes mid-instruction (2026-09-19:
  the lock-on in-mover hook silently ran `push rbp; adc bl, dh` for two builds; the effect
  draw-loop hook crashed the game at boot). Conditional/short jumps inside the stub are
  assumed 2 bytes long; keep labels within 127 bytes.
  `?N` rip-relative cells must be in trampoline memory (`trampoline->Pointer<T>()` /
  `RawSpace`) or inside the game image; a DLL static can sit more than 2 GB away and the
  32-bit displacement silently wraps (2026-09-19: crash on the first effect draw).
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
- **`[Diagnostics] DataRing=1`** (2026-09-26): keeps the last 6 s of the whole `.data` section (60 snapshots,
  100 ms, ~234 MB) and writes them to `<ini>_dataring_N.bin` on `*` (numpad, or Shift+8; F keys are used by
  the game; HangWatch leaves `*` alone while it is on). `docs/tools/dataring_scan.py` lists values that were
  idle, ran and went idle again, with their rate per second (a per-render counter moves ~fps/10 per snapshot).
  Found the message-window timer in one capture. `WriteWatchMinutes` (default 3) keeps the write watch armed
  longer than the first 3 minutes after launch.
- **Scene tracing** (2026-09-26): `TraceScriptOps=1` + `TraceScriptStreamChannel=0` + `TraceScriptStreamAll=1`
  writes every parsed script command to `<ini>_scriptstream.tsv` (ms, op, ch, pc, record, script, a0..a2 =
  the thread's argument slots when written); `TraceScriptStreamCutsceneOnly=1` keeps only game mode 1 (it
  dropped part of a menu-launched scene, so prefer full traces for short sessions). `docs/tools/atelydis.py`
  decodes ATELY modules from `dump/cutscene_audit` resources (functions, labels, string refs).

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
| `0x6D1CEC` | upstream's cutscene gate cell (with `[0x658F70]==1` it skips the X/Z speed scaling). **Live, not dead** (2026-10-31): script opcode `0x88` (`0x140360940`) writes it at `0x1403609BA` as slot 0 field `+0x85C` of the table `[[0x140659B18]]` = `0x1406D1490` |
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
| `+0x940` / `+0x944` | MP / max MP; fractional accumulator (signed short) at `+0x9be` |
| `+0x948` / `+0x94c` | ability gauge / maximum; fractional accumulator (signed short) at `+0x9c0` |
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
cutscene gate reads `0x6D1CEC`, which script opcode `0x88` can write (2026-10-31 correction: the cell is live, so the gate can open in game mode 1 while an event script runs; the fixes that mirror the gate then stay stock there).

## 4. Motion profiles, movement dispatcher, battle script

**Judecca cutscenes (2026-09-19):** encoded CMD5F (trace op5E), handler
RVA0x35F520, returns global0x657944. Native0x1EF170 counts available actors in
the three active party entries (death flag plus native transitional exceptions).
Transition scene7553 and final-boss approach scene7555 both test `CMD5F()>2`
before playback. User's failing snapshot counts1 (Queen plus two dead actors),
working snapshot counts3 (Queen plus two different living actors). This is a
native script gate, independent of FPS. An opt-in partial-party candidate is
under runtime testing; it is not a verified fix yet. See
[full evidence and limitations](JUDECCA_CUTSCENE_DIAGNOSIS.md).

**Empty cutscene participants (2026-09-19):** model getter0x1C0320 returns-1
for an empty slot; dead actors can still return a valid model. Final scene7555
was extracted from installed pack4.pac (raw deflate, FND ID30948); its commands
address PC_0/PC_1/PC_2. Resolver0x383E60 returns-1 for missing names. CMD4 and
CMD219 treat negative channels specially (first type3 actor); use a positive
out-of-range channel to take their missing-actor path. Native range0..65.
Scene manager pointer0x659E88, scene ID+0x10, stage+0x48; stages5/6 init/main,
8 closing,9 cleanup,11 temporary restore. No replacement actor/roster writes
are needed by the v2 candidate; actual playback still requires user validation.

**Runtime refinement (2026-09-19):** an empty party slot can retain a nonnull
actor pointer and PC_1 -> channel1 binding, while class+0x360/model+0x2B8 areFFFF,
HP/maxHP0/0, active-party character byteFF. It accepts queued animations but
has no model to complete them. V2 stalled at final-scene CMD4(PC_1, handle) at
bytecode0x3EC8 after CMD3(67,0). Treat this placeholder as absent when resolving
scene PC names too; checking only failed lookup-1 is insufficient. V3 applies
that refinement based on the empty-slot mask captured at the eligibility gate.
Genuine dead actor model9 animated with HP0/death1 in the same scene snapshot.
**V3 runtime verified:** final scene7555 with Queen/model10 alive, empty slot1,
dead model9 slot2 at120 FPS plays to completion and enters battle. Trace passes
the prior empty-actor wait and reaches main's natural end, closing and term.
Before/after HP/death bits, native count1 and entire active-party table match.
Capture `partial_party_v3_run_20260919_210929`; other scenes/compositions remain
unverified in game.

**Whole-game static audit:** see [CUTSCENE_PARTY_AUDIT.md](CUTSCENE_PARTY_AUDIT.md).
Eleven pre-playback full-party guards target ten scenes; seven other scenes have
internal main/closing early returns for partial parties. cut7855 already branches
on1/2/3 participants; do not spoof CMD5F globally. cut7558 uses getPCModel4/CMDEF
to create separate type3 cinematic actors from stored character selections.
CMDEF handler0x363EB0 allocates0xEA0, constructs via0x192450, registers0x1ABC90,
loads model0x1B7FE0, binds name0x384020. This differs from7555's existing PC actors.
No universal casting fix is implemented or implied by this static audit.

**Temporary scene actors, first candidate:** [JUDECCA_STAND_INS.md](JUDECCA_STAND_INS.md)
documents CMDEF/CMD27C creation before the stage5 resource wait, category3 free
channels6..47, name-registry ownership at entry+18 and native384960 cleanup.
Opt-in JudeccaStandIns fills empty slots in7555 only; runtime verification pending.
**V2 runtime verified:** user confirms Ace animates and battle begins. Native
CMD21 preloads7/67/68/69/71/2400 before stage5; all six requested clips match
actor motion in capture standin_v2_run_20260919_220130. Temporary actor deleted,
party table/HP/death unchanged. Verified7555 with10/-1/9 only.

**Expanded partial-party profiles (experimental):** see
[CUTSCENE_PARTY_EXPANSION.md](CUTSCENE_PARTY_EXPANSION.md). PartySceneFix1
handles17 reviewed scene IDs through33 exact-module CMD5F sites, retaining
count0/full-party and7855's native partial-party branches. Ten profiles use
scene-specific PC animation preloads; seven retain native casting. Full ATELY
fingerprints include constants and names, verified against both real Judecca
mission captures. Scene preparation independently verifies its loaded module.
Native34B880 calls34D5C0(engine+8,code); the latter allocates the0x158 script
object into the inline pointer array atengine+0x10 (first script). New scene
preparation resets arming. No party/HP/death writes added. Helper/clip/corpus
checks and Release build passed; expanded-mode runtime validation PENDING.
**Expanded-mode7555 regression now passed:** user confirms playback; capture
expanded_run_20260919_230804 verifies both module checks, all six PC clips,
native deletion1, identical active-party table and unchanged HP/max982/982,
0/0,0/546. Other16 scene profiles still lack runtime verification. User asks
to leave this build; diagnostic scene snapshots disabled again.

**Death overlay report:** user sees four copies of darkening with normal3D scene,
2560x1440/120 FPS. Diagnosis and read-only capture build in
[DEATH_OVERLAY_DIAGNOSIS.md](DEATH_OVERLAY_DIAGNOSIS.md); no visual fix established.

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
  without rendered frames, or numpad `*` / Shift+8: thread RIPs + stacks, evaluator state, script rings, per-channel
  script dumps `<ini>_script_*.bin`), `TraceScriptOps` (default 1; ring of the last 512 commands and
  a spin-filtered ring of the last 512 distinct-PC commands), `WatchActorVar = ch,idx` (DR0 write
  watch on an actor variable). Tools: `docs/tools/scriptdis.py`, `calls_to.py`.
- **Chapter 4 mission 1 pursuer "Supersoldier Akkad" at 120 fps - SOLVED 2026-09-16 (`ScriptSpeedPerFrame`)**.
  Akkad is **channel 6** (state `0x200E`, hp 41250, behaviour script `m_bangaisha1_01_ai`, one
  function id 0x56). ch11 (`0x2019`, 1400 hp, stands still all fight) is what `TraceBossPos` and the
  boss-class-filtered fixes pick - everything traced on ch11 on 2026-09-13 (incl. `AiBrain30Hz`) was
  the wrong unit. Symptom: at 120 fps he walked while the player stood still and stopped within
  0.4-0.6 s of the player moving; at 30 fps he followed for 6-8 s legs.
  ROOT CAUSE (script, not engine): `_StateBtlMove` steers every tick (`CMD111(own heading,0,0)` ->
  `actor+0xd00=0xF/+0xd04`, consumed by the mover `0x1401aa430`, zeroed every frame) and calls
  `FuncPlanCheckMove` each tick = a STUCK CHECK: `d2 = (X-lastX)^2+(Z-lastZ)^2` per tick vs
  `0.3 * CMD66()^2` (CMD66 = `[actor+0x110]`, speed per 30 Hz frame); stuck when
  `(d2 <= 0.3*v^2 && d2 < previous d2) || (d2 == 0 && previous != 0)`. Per-actor scripts tick every
  rendered frame, so at 120 fps `d2 = (v/4)^2 = 0.0625 v^2` is always under the threshold and any
  slowdown while steering after a moving target flags "stuck" -> `_AttackSelect` -> `_BtlMoveSelect`
  -> after 2-4 moves `_StateBtlWaitInit` requests action 26493 (queue cmd 1C = yuso6 command script
  fn 0x16: `SetCloseTargetDistance`, `AiSetUCTargetProbability(100)`, then `IdleNormal` for 60 ticks)
  -> `_StateBtlWait`. At 30 fps `d2 = v^2` never trips. The same library (CMD66 at offset 24304 of the
  ch7/ch8/ch11 scripts of earlier chapters) is used by other enemies.
  FIX shipped: `[Movement] ScriptSpeedPerFrame` (default 1): the CMD66 handler `0x14035f910`
  (`movss [rbx+0x30], xmm0` at `0x14035f947`, sig `BA 02 00 00 00 E8 ? ? ? ? F3 0F 11 43 30 48 83 C4 20 5B C3`)
  multiplies the returned speed by 30/fps. Verified 120 fps: legs 3.9/3.9/8.0 s while the player runs,
  Akkad chases continuously. `AiBrain30Hz` stays experimental/default 0 (it never applied to Akkad:
  type-2 actors run the script AI `0x1402744f0`, the brain sites `0x140194b49/bd6` are not on their path).
  Diagnostics added 2026-09-16: `[Diagnostics] TraceBrain=<ch>` (ring of brain results at those two
  sites, dumped by `*`; empty for script-AI actors).
  Script tooling facts (2026-09-16): op handler table `0x140612368` (48-byte entries) is indexed by
  `bytecode cmd id - 1` (bytecode `CMD99` = ring index `0x98`). Handlers: CMD111 steer/walk
  `0x14034e600`, CMD157 walk-toward-actor `0x140353c90`, CMD128 StopMove `0x140351370`, CMD112 distance
  `0x14034e8b0`, CMD113 bearing `0x14034ea30`, CMD41 heading `0x14035e790`, CMD13C normalize angle
  `0x1403525f0`, CMD3E/CMD40 own X/Z, CMD66 speed `0x14035f910`, CMD61(ref) = call script function by
  NAME (`0x14035f560`: name table at `code+0xc` {count; 8-byte entries {?, id, offset, len} + strings};
  function bodies via `hdr+0x138` table (count = `[t138+8]>>16`, 24-byte entries
  `{?, ?, hash lo, hash hi, offset, len}`, hash = `0x14034d2f0`: 8-byte accumulator, byte i added to
  acc[i&7]); `CALLn` = same name table), CMD99 state byte `actor+0x9ab`, CMD21B global flag bit,
  CMD169(a,b) random, CMD123(n) property getter `0x1401a2080`, CMD4F play-motion (request ring
  `actor+0x6c4`), CMD4 wait-for-request, CMD219 clear ring, CMDA wait. Script dumps come from the `*`
  (numpad multiply / Shift+8) HangWatch report - there is no F7 key. Dump layout: 0x200 object header +
  code; code: 0x20-byte file header, functions `{id, len}` + 8 bytes, body at +16.
  `docs/tools/scriptdis.py` still desyncs on some statement forms (8-byte blocks after labels, function
  entries) - hand-decode with the word dump when needed; ring PCs (= command start + 6) are reliable anchors.
  Statement types executed by the VM step `0x140371390`: 1 control, 2 command, 8 call, else expression
  (`0x1403721c0`, operand types only 4/5/6/2/8; len = word>>4 bytes).
- Unresolved: Banz99's "global counter increasing by 1 each game cycle" that event scripts compare
  against (ship-jump enemies at frames 210/225 in his save) — not yet located; may be a store-1/2
  script counter (now deduped) or an engine command result.

### Chapter 4 Vajra / vehicle blocking the exit — local fix passes; wait rollback still falls (2026-09-17)

- **General fix runtime PASS, limited to this scene:** user confirms scene passes
  normally with all recent gameplay fixes restored. Capture
  `dump/vajra_test/script_motion_run_20260917_225012/`, ASI MD5
  `C0997A8316441B6676B6F153C77EDDF2`, cap120, no ASM FAIL/MISS/ABORTED.
  CMD11C1286 at167.406s, snap/1288 at170.766s (3.360s versus native3.344s),
  property29=7 at174.125s, final shooting1289 at174.141s. Exactly one recovery
  line: ch6/motion1286/pc10988/request29/raised19350/poll19351/age1. This confirms
  the general wrapper recovered the missed pulse in the full configuration.
  It does not prove other campaign scenes are unaffected. No independent claim
  of exit traversal beyond the user's overall scene-pass report is made.
- User highlighted regressions in already-completed chapters. Added
  `docs/REGRESSION_TESTS.md` with current-build versus historical coverage and a
  short replay set (Qator/ch3 transition first). Promoted the actual-helper checks
  from ignored scratch files into `docs/tools/test_script_motion.py` and
  `docs/tools/tests/script_motion_cases.cpp`; run passed with assertions enabled.
  Tests need no game/dump files and can be rerun against future source. They test
  helper behaviour in mocked memory, not complete scenes or native event ordering.
  No gameplay/config/binary changes were made in response to this concern.

- **Native Wait control PASSES:** user confirms final position reached, no `*`
  marker. Continuous capture `dump/vajra_test/native_wait_run_20260917_223719/`
  verifies NativeScriptWait1 at120FPS. Motion-context script pointer25B0AF26A70
  requests1286 at150.063s, snaps/requests1288 at153.422s: 3.359s vs native3.344s.
  Final shooting1289 at158.797s and stable position(-73,1418,10192) appear.
  The saved binary for that pointer is not the later motion module (pointer reuse);
  do not blindly decode its bytes as m_scorpion3. Executed PCs/opcodes and positions
  corroborate the transition using the earlier verified motion-script mapping.
  This one targeted control supports a wait-cadence/transient-event mismatch:
  upstream wait dedup can miss the pulse; the fractional wait fix alone can too.
  Removing wait scaling is diagnostic only, since it restores fast waits/dodges.
- **General replacement implementation (scene pass above):** experimental
  default0 `ScriptMotionEventFix`, requiring AiEventKeepFix1 and FPS>30. Shares the
  verified event-clear capture bridge and native-first CMD160 wrapper with the
  local fallback, taking precedence if both switches are enabled. No actor-class
  or scene filter. Covers ONLY selector1/bit1 completion queries, not arbitrary
  event bits, CMD161 or all long waits. Does not mutate the game's live event words.
- Capture records actual completion pulses per actor/motion/request, with lifetime
  ceil(fps/30) renders. Reader state is keyed by context/script/PC/actor/motion/
  request; only a reader that previously returnedfalse and polled within one
  native frame plus one render can recover. Existing pulses are not given to new
  readers. Native success counts as observation; a pulse is not reissued in later
  renders, while repeated reads in the delivery render remain true. Different
  readers observe independently. Same-clip request restart (`actor+40`) resets
  state. Fixed1024-slot reader map collisions discard history (native fallback),
  not another reader's delivery. This bounded scope deliberately leaves rarer
  long-wait/reuse/collision cases for further evidence rather than holding all
  events indefinitely. Capture still occurs at the existing clear site.
- Actual production helpers extracted/compiled by
  `dump/vajra_test/check_script_motion.py`: assertions enabled, pass for all120FPS
  recovery phases, repeated reads/no later duplicates, expiry/inactive/new readers,
  independent readers/native observation, actor/motion/request/script/PC changes,
  other event bits, frame wrap and collision fallback. Shared bridge keystone
  check passes197bytes/57statements; Release Win64 build passes (existing warnings).
  These checks are not broad gameplay validation.
- the test PC now MD5 `C0997A8316441B6676B6F153C77EDDF2`, FpsCap120,
  ScriptMotionEventFix1; restored ScriptWaitFrameFix/MotionStartWaitFix/
  DodgeCadenceFix/MpRegenFix/ScriptSpeedPerFrame to1; VajraEventFix0,
  NativeScriptWait0. Diagnostics retained. Backup
  `dump/vajra_test/script_motion_deploy_20260917_224310/`. User closes game after
  every test; do not repeatedly ask for closure. Next run tests the general
  completion fix with native-equivalent waits and the gameplay fixes restored.

- **Grouped recent-fix rollback also fails:** user reports the same behaviour;
  `dump/vajra_test/without_recent_run_20260917_222757/` confirms cap120, no recent
  fix init lines, and the same clip1286 stall. Motion script1D70AE66A70 starts1286
  at153.641s, keeps polling completion through164.969s, never reaches29EA/29FC,
  property29=7 or clip1289. Position reaches(-16636,-9396,21365). These recent
  changes are not necessary for this failure; older fork/upstream patches remain.
- **Previous native-Wait diagnostic build:** new default-OFF
  `[Diagnostics] NativeScriptWait=1` bypasses ONLY the CMDA countdown patch at
  RVA35C921, leaving the original game handler (subtract1 per rendered frame).
  It takes precedence over ScriptWaitFrameFix inside the existing counter-fix
  group. DisableCounterDedup already bypasses the whole group and is NOT needed.
  This isolates the upstream wait dedup without also disabling script-variable,
  fade/demo-wait, projectile or animation fixes. Local origin/master contains the
  same wait dedup algorithm: ScriptWaitFrameFix0 was never an unpatched-Wait test.
  Release build passed; unique signature/handler offset checked against dump.
  Keep the previous six disabled switches/cap120 for the next run. This bypass
  intentionally restores frame-dependent waits and is not a permanent fix or
  proof of fault in upstream code. Deployed to the test PC after the user confirmed
  they close the game after each test; MD5 `7143352B15EE218A19DB22C7505A2BB6`,
  NativeScriptWait1, cap120 and all six previous switches OFF verified. Backup:
  `dump/vajra_test/native_wait_deploy_20260917_223137/`. Result recorded above.
- **Grouped control configuration:** the test PC additionally disables
  MotionStartWaitFix, DodgeCadenceFix, MpRegenFix, ScriptSpeedPerFrame. The latter
  was absent from INI and defaulted1; explicitly added0 in the Movement section.
  FpsCap120, ScriptWaitFrameFix0, VajraEventFix0, all other settings and ASI remain
  unchanged. Backup `dump/vajra_test/without_recent_deploy_20260917_222252/`.
  This tests a group of recent changes, not an unmodified/upstream120FPS build.
  The repeated failure above directs investigation back to shared event delivery.
- **Latest controlled rollback:** `ScriptWaitFrameFix=0`, `VajraEventFix=0`,
  FpsCap120, same ASI MD5 `95221E0BFDD6F56A4E2EDAE3E973B522`; other switches
  retained, including MotionStartWaitFix/DodgeCadenceFix/MpRegenFix. Captured in
  `dump/vajra_test/without_wait_run_20260917_221432/` (only current log/stream and
  script pointers beginning206C27 identify this run; the folder also contains
  older diagnostic files copied from the game directory). No hook errors.
  User reports both vehicles destroyed, then Vajra falls instead of reaching her
  final position. Roster confirms both vehicle proxies ch9/ch11 class2096 HP0 and
  physical ch8/ch10 class2032 at X60000; destruction occurs before final movement.
  Thus second-vehicle destruction does NOT universally require final shooting
  clip1289; the earlier successful native run's ordering was not a universal rule.
- In this rollback, clip1286 starts at stream189.406s. The same CMD160(1,1) loop
  keeps polling through205.656s; no snap at29EA, clip1288 at29FC, property29=7,
  or final shooting clip1289 occurs. Position reaches(-25243,-15695,28537).
  Poll observations are mostly31/32/47ms apart even with ScriptWaitFrameFix OFF
  (stream drain timestamps are not exact execution frames). Motion script bytes
  through the function/name-table boundary match the earlier broken run.
  This reproduces the same stuck movement WITHOUT the recent wait change and
  falsifies its being a necessary cause. It does not establish stock120 behaviour,
  exonerate all other patches, or show that the wait change cannot affect event
  timing. Actual exit traversal remains unconfirmed separately from destruction.
- That first control required only INI changes; no source or binary
  change was made for this result. Do not leave ScriptWaitFrameFix OFF as a final
  repair: that restores the previously measured dodge-cadence error. The general
  replacement was subsequently implemented and passed this scene as above.

- **Previous fixed result:** user reports the scene passed normally at120FPS with
  VajraEventFix1 and is continuing to play. Fresh live snapshot preserved in
  `dump/vajra_test/success120_20260917_215734/`; no ASM FAIL/MISS/ABORTED.
  Log records **motion1286, pc10988, raisedFrame21033, pollFrame21034, age1**:
  native CMD160 returned0, while the captured real completion pulse was one render
  old; recovery returned1. This confirms the lost-pulse mechanism for this run.
  CMD11C1286 starts at180.985s; position snap and CMD11C1288 at184.344s (3.359s vs
  native3.344s); property29=7 at187.704s, final shooting clip1289 at187.719s.
  Earlier motion271/292 recoveries also appear (nine total captured), so the fix
  is restricted by actor class0x206A and event query, NOT by location/action07 only.
- **Relationship to recent changes:** ScriptWaitFrameFix corrects CMDA(1) from a
  possible one-render wait (~8ms at120) to one native frame (~33ms). Vajra's loop
  uses exactly this wait; an animation completion pulse can be cleared before the
  next query. This initially suggested a regression from that change; the rollback
  above now reproduces the failure without it. Keep the demonstrated missed-pulse
  mechanism separate from the disproven necessary-cause hypothesis.
  MpRegenFix does not touch this wait/event path.
- Main stream/position/movement traces are bounded to15min (different
  start points); parser/queue hooks and lightweight logging remain until exit.
  Diagnostic switches are read at startup, so INI edits do not stop this session's
  watchers. Diagnostics remain enabled for this investigation.

Earlier investigation and implementation details follow chronologically:

- Latest user report and continuous 120-FPS run supersede the earlier missing-shot
  interpretation below: two shooting actions DO happen, the second vehicle remains,
  and Vajra leaves the roof. Its normal scripted departure is expected only after
  clearing the obstruction. Preserve the distinction between visible shots and
  actual damage/destruction; no projectile root cause has been established.
- Corrected user report on the test PC at 120 FPS: Vajra climbs the building, fires the
  FIRST shot and hits the first vehicle. The SECOND shot never happens; instead
  Vajra starts falling and disappears, leaving the second vehicle blocking the exit.
  This supersedes the initial "shoots but misses" description. No cause or 30-FPS
  comparison is confirmed yet; do not assume a projectile targeting defect.
- Original log and INI preserved in `dump/vajra_test/initial_20260917_210058.*`.
  Current build includes the verified dodge and first-observation MP fixes.
  No ASM FAIL/MISS/ABORTED; existing nonunique-pattern warnings remain. The log
  contains no HangWatch report. Fresh log, six reports and script dumps are now
  preserved in `dump/vajra_test/capture_20260917_211554/` (the reports cannot yet be
  assigned unambiguously to the user's two gameplay markers).
- Fresh motion module `m_scorpion3` is observed on channel 6. Later snapshots repeat
  its `_foot_step_common` (body `0x2ad4..0x2dc2`), polling CMD160 event bits and waiting
  with CMDA(1). This loop is shared by actions: it does NOT alone identify which
  parent action failed. Field module contains BOSS_AI phase calls `IdleSecondMove`,
  `IdleSecondAttack`, `IdleThirdMove`, etc.; their external implementations are not
  in that field module. `dump/vajra_test/decode_nested.py` handles nested function
  containers that the older linear decoder misreads; argument types still need
  manual checking (constant pool entries are not all floats).
- Added opt-in read-only diagnostics: `[Diagnostics] TraceBossChannel=6` selects
  channel 6 for existing `TraceBossPos=1` position/profile/AI telemetry (15 minutes);
  default -1 preserves the old boss-class selection. `TraceScriptStreamChannel=6`
  with `TraceScriptOps=1` continuously drains the parser ring to
  `FFT0HD Unlocker.ini_scriptstream.tsv`, saving encountered channel-6/global script
  modules as `ini_stream_<address>.bin`. TSV timestamps are poll times, opcodes are
  command IDs minus one, PCs are after the 6-byte header. Lost ring entries are
  explicitly marked; resolved script pointers are sampled asynchronously. No new
  game-code hook or gameplay fix is introduced by this diagnostic addition.
- Diagnostic build compiles successfully; deployed to the test PC after the user closed
  the game, MD5 `26DC1417584F9BB9F4A516F5FDAA9188` verified on both sides. FpsCap=120,
  the above diagnostics plus TraceCmdQ=6 enabled; gameplay switches unchanged.
  Previous ASI/INI/final log backed up in
  `dump/vajra_test/diagnostics_deploy_20260917_212549/`. Runtime validation pending.
- Diagnostic runtime validated: `dump/vajra_test/run_20260917_213453/` contains the
  120-FPS log, 18.9 MB TSV (no reported ring overruns), and fresh `ini_stream_*`
  modules. Many copied `ini_script_ch*` files are OLD; use fresh stream addresses or
  the current log to identify relevant modules. Vajra is class **0x206A**, channel 6;
  actor+0x884 stays 0x611E during multiple clips and is not the active clip ID.
  Stream start tick=3261437; BossPos timestamps have +15703 ms offset to stream time.
- At stream 189.188 s and 193.641 s, motion module `1F3C28C6A70` starts `_shot_common`
  clip 1284 (CMD11C), each issuing 10 CMD131 projectile requests. At 198.078 s it
  enters **attack07**, property29=6, clip1286, then calls `_foot_step_common`.
  Its CMD160(1,1) poll (ring PC10980) repeats roughly every33ms until game exit;
  the scripted position snap at attack07 PC0x29EA and final clip1288 are never
  reached. At ~201.5 s position is (-2704,800,9756); by ~322 s it is roughly
  (-212819,-152970,184830). This is unbounded motion, not a completed normal escape.
  Missing completion event is a hypothesis, not yet observed at its producer.
- The first obstruction's physical actor ch8 is moved to (60000,0,60035), HP0,
  at BossPos~164188ms; proxy ch9 also HP0. The second physical actor ch10 and proxy
  ch11 remain alive. Field truck damage scripts require two qualifying damage
  callbacks before setting their respective progression bits (TRK03: bit6,
  TRK05: bit8). An attack request alone does not establish that a truck was hit.
- External AI module now captured: `ini_stream_1F3C28DC990.bin`,
  `m_scorpion3_01_ai`. IdleSecondMove requests24863, IdleThirdMove24865,
  IdleFourthMove24867. Those are actor actions, distinct from clip IDs.
- Static handler check: CMD160 is `0x140354160`, reads bit directly from AI words
  (selector1 -> +0x1a0); CMD161 is `0x1403541e0`, waits on the same words. No history
  is retained by these handlers. Existing AiEventKeepFix counts *any* VM runner
  invocation, not an actual per-actor event poll. With the newer CMDA Wait(1)
  correction a polling loop can sleep across rendered frames. Whether a completion
  pulse is cleared in this gap requires a producer/poll trace or controlled test;
  do not treat the old "VM ticks at30Hz" source comment as established scheduling.
- After preserving this run, the test PC FpsCap changed120->0 for native30FPS reference;
  ASI unchanged (MD5 above), diagnostics remain enabled. User asked to repeat the
  same scene, mark shooting/departure with *, then close the game. `_wfopen_s`
  holds the TSV against copying while open; close before collecting it. No gameplay
  code changed for Vajra yet.
- **Native30 comparison passes** (user destroyed both vehicles, entered next area,
  then closed). Files: `dump/vajra_test/native30_20260917_214320/`. At stream203.500s
  attack07 starts clip1286; at206.844s (3.344s later) it exits the event-poll loop,
  snaps to (-2343.4,1461.3,10191.5), starts clip1288, and at210.172s reaches property29=7.
  It then moves to the final firing position (-73.441,1417.54,10191.5), shoots with
  clip1289, destroys the second truck, and remains visible. At120FPS this whole
  continuation is missing after clip1286; the earlier shooting from (842.7,2132.45,
  7965.41) is NOT the final firing stage. No reason to alter projectile aim yet.
- **Experimental VajraEventFix** added default0, requires AiEventKeepFix=1 and FPS>30.
  Before the existing AI-event clear hook erases +0x1a0, capture bit1 for class0x206A
  only. CMD160 handler cell `base+0x612368+0x15f*0x30` is verified to point to354160,
  then wrapped: call native first; only CMD160(1,1) may consume a saved pulse once,
  within ceil(fps/30) rendered frames. Actor pointer/active clip(+0x5c8) changes
  invalidate it; a successful native query marks it already delivered in that
  frame. Engine event words, other selectors/bits/classes, projectile rules and
  movement speed are unchanged. Recovery logs `[VajraEvent] recovered` with clip,
  PC, raised/poll frames and age. This is a targeted test of the lost-event hypothesis,
  not yet runtime-proven; do not call the softlock fixed before the next run.
- Capture bridge preserves flags, volatile GPRs and XMM0..5, reserves Win64 shadow
  space at a leaf function site with RSP%16=8. Keystone assembly passes (197 bytes);
  real extracted C++ helper tests pass all four120FPS poll phases, single delivery,
  expiry, new-clip invalidation, native observation, other class/bit isolation.
  ASI builds successfully. TSV now uses `_wfsopen(...,_SH_DENYNO)` for live copying.
  Build deployed to closed the test PC, MD5 **95221E0BFDD6F56A4E2EDAE3E973B522**, FpsCap120,
  VajraEventFix1, prior gameplay switches preserved. Backup:
  `dump/vajra_test/event_fix_deploy_20260917_214909/`. Awaiting user test.
- Static leads only: upstream general projectile hook at `0x140287c20` adjusts
  effect displacement `+0x54/+0x58/+0x5c` and matching XMM6-XMM12 values by 30/fps;
  gravity/bounce patches are separate. The grenade speed-clamp pattern expected
  twice actually matches RVAs `0x292cc0`, `0x292fb0`, `0x293cd1` (already logged
  by prior builds). None is yet tied to Vajra. A separate broad damage gate at
  `0x140470700` is labelled player/AI projectile damage in source, but its actual
  role in this field encounter has not been established. Do not change broad
  projectile/collision patches merely from these comments or warnings.

### Chapter 4 final boss (Vajra in the arena, `m_scorpion3`, ch6 class 0x206A) — freeze after a landing at 120 FPS (2026-09-18, UNDER TEST)

- **Report:** the boss "stalls" late in the fight (HP 47%). Session log
  `dump/vajra_test/ch4boss_run_20260917_234609/` (the test PC, MD5 `C0997A8316441B6676B6F153C77EDDF2`,
  cap120, ScriptMotionEventFix1, no hook errors, zero `[ScriptMotionEvent] recovered` lines).
  Log time 885.08–886.72 s: a jump from (72,0,3142) to (-928,0,924), Y peaks at 1000, mover
  speed 72.79, lands at Y=0 (`%.0f`). From 886.7 s to the end (900 s trace bound, game closed
  at ~935 s): position, facing and `dest` frozen, `ccc=0 cd4=16` (no movement leg ever starts
  again), AI block `+0x550` id stays 13 with flags `C00400`, HP keeps dropping 6132→3306 (the
  user hits a boss that does not react). Not a physics stall: the mover is idle, not falling.
- **Trace gap:** the script stream and the BossPos/AI traces were bounded to 15 min from
  DIFFERENT starts: stream `ms` = log `+ms` + 15.7 s (anchors: `CMD1` wall snap at stream
  880.531 ↔ log 864.813 `pos=(20,806,-3597)`; first field-script command at stream 730.9 ↔
  boss spawn `BossDiff +715313`). The stream therefore ends at log 884.3 s, 0.8 s BEFORE the
  fatal jump. New `[Diagnostics] TraceMinutes` (default 15) lengthens every bounded trace; the
  the test PC ini now has 45. Do not align stream and log timestamps without an anchor.
- **What the stream does show (last 2.5 min of the fight):** the boss cycles
  `battle_idle/BattleIdleNormal → _charge_common (clips 956, 2159) → _jump_common (51) /
  _jump_to_wall (51) → _wall_machine_canon (55, 1431×) → _jump_from_wall (173)` plus missile
  and canon attacks. The fatal jump follows two `_charge_common` starts (log 881.4/883.55 s),
  i.e. it is `_jump_common` or `_jump_to_wall`; both end in the same loop:
  `while (v==0) { if CMD160(1,0)==1 {v=1; CMD147; CMD14B} ...turn to target...; CMDA(1) }`
  — a 33 ms poll of **selector-1 bit 0** (the landing keyframe), exactly the lost-pulse
  pattern of the roof scene but on bit 0 instead of the completion bit 1, which the
  general fix did not cover. `_jump_common` sets `CMD4C(86,1)` before the loop and
  `CMD4C(86,0)` only after it, so hits do not interrupt the stuck loop (flag 86 →
  `actor+0x9a9/+0x95e/+0x95f`, the "no hit reaction" group). Same-run counter-evidence
  that keeps this a hypothesis: ~10 earlier landings in the fight polled the same bit fine,
  and an earlier `_jump_from_wall` (stream 885.9–886.9) missed ITS completion pulse
  (branch `CMD151(10,0); CMD4C(66,1)` never ran) without freezing the boss.
- **Engine facts verified for this fight (Ghidra, `docs/tools/find_field_refs.py`):**
  `CMD3E/3F/40` = mover X/Y/Z through actor vtable `+0x28` = `0x1401B8410` (mover
  `+0x08/+0x0c/+0x10`, the same cells `[BossPos] pos=` prints). `CMD16(v,-1)`/`CMD17(v)` =
  speed `+0x2a0`(+`+0x298`)/accel `+0x2a8`. `CMD151(n,v)` = actor param setter `0x14019C620`:
  10 → `+0xce4` **virtual floor offset** (added to the collision floor in `0x14019AF50` /
  `0x14019C110`; the wall top is param10 = 868), 11 → `+0x10c` speed cap via `0x1401BA880`.
  `CMD4C(flag,v)` = flag setter `0x1401A4540`: 66 → `+0x6b9` bit 2 = **floor snapping** (the
  vertical servo in `0x14019C480`: when set, moves the actor toward floor+param10 each
  frame; `+0x6b9` bit 0x20 = ballistic mode with gravity `DAT_14065598c`, bit 0x40 = landed;
  landing snaps Y through vtable `+0x38` and raises NO event — bit 0 is an animation
  keyframe). `CMD111(heading,1,1)` = walk setter `0x14019B8E0` with bit 2 of `+0xcd4` set →
  state 1 only writes heading `+0xd04`; the jump displacement is clip root motion (mover
  speed 72.79 during clip 173). `CMD147/CMD14B` → AI-block functions `0x140279E00` /
  `0x140277B30` (not movement). `CMD369()` = global `[0x14057fdbc]` unless game mode 5/8;
  `CMD123(n)` = property getter `0x1401A2080` (property 323 is what the field script waits
  for together with CMD369 to enter its state 3). Script stream: `op` = command id − 1,
  `pc` = command start + 6; the field script `main` re-runs every render (3 commands per
  frame is normal, not a stall).
- **Change under test (source commit after `d33b8ca`):** `ScriptMotionEventFix` now keeps
  missed pulses for EVERY bit of the selector-1 word per polling script (same reader rules:
  must have polled false within one native frame + one render, pulse ≤ ceil(fps/30)
  renders old, one delivery, per-bit sequence). `[Movement] ScriptMotionEventMask` (hex,
  default `FFFFFFFF`; `2` = old behaviour). `[Diagnostics] TraceAiEvents=<ch>` logs
  `[AiEvent] ch frame word1a0 word1a8 word1ac` at the clear site (≤20000 lines) so raises
  can be matched to stream polls; `[ScriptMotionEvent] recovered` lines now carry `bit=`.
  Helper tests extended (`docs/tools/test_script_motion.py`: bit-0 phases, per-bit
  independence, mask, selector/bit range) and pass. Deployed to the test PC MD5
  `5D34D8613C43A626F9E60F4049221EF3`, ini adds `TraceMinutes=45`, `TraceAiEvents=6`; backup
  `dump/vajra_test/ch4boss_deploy_20260918_000500/`. Next run: replay the arena fight at
  cap120; expect either a `recovered ... bit=0` line at a landing with no freeze, or a
  complete stream through the freeze that points elsewhere (check `_jump_common` PCs
  0x3AFC..0x3ED0 in the module saved as `ini_stream_<ptr>.bin`, and `[AiEvent]` raises).
- **First replay on the new build (2026-09-18 00:30–00:42, `dump/vajra_test/ch4boss_pass_20260918/`):**
  boss killed (HP 0 at log 185 s), no freeze, no hook errors — but **zero**
  `[ScriptMotionEvent] recovered` lines, so this pass does not exercise the fix and does
  not prove it; the freeze is phase-dependent. What the run does establish from 1694
  `[AiEvent]` lines: event raises on `+0x1a0` normally last 4 renders (one animation frame
  at 120 fps), but a minority are shorter — bit 0 (landing): 111 raises of 4 frames,
  6 of 5, and 19 of 1–3 frames (7 of exactly 1); bits 1–3 show the same tail. A script
  polling every 4 renders (CMDA(1) with ScriptWaitFrameFix) can straddle a 1–3-frame
  raise, which is the loss mechanism the widened fix covers (age ≤ 4). Boss-module
  CMD160 polls in this fight: 203 at the `_jump_common` landing loop, 93 in
  `_jump_from_wall`, 15 in `_jump_to_wall`. Keep the diagnostics on for more fights;
  the first `recovered ... bit=0` line with a normal continuation is the confirmation.
- **Second replay (00:42–00:51, `dump/vajra_test/ch4boss_long_20260918/`):** user deliberately
  prolonged the fight (boss killed at log 260 s), 1832 `[AiEvent]` raises, again zero
  recoveries, no freeze. Two clean fights ≈ 600 landing polls without a single lost pulse,
  so the loss is rare. Build `766B7AB648187817975B1F0C2AB202DC` (deployed 00:54) adds
  `[EventPoll] ch frame bit native pc` for the `TraceAiEvents` channel (≤60000 lines, own
  counter) so poll phase can be measured against `[AiEvent]` raise windows on the same
  frame counter: for each poll, which frame of the raise it hit, and how many raises
  were never polled (a native miss would show as a raise with no poll inside its window
  followed by a later true poll, or by the stuck loop).

### Scripted walk-to-point creeps at 30/fps of native speed ("runs on the spot at the wall", Akademeia portal) — FIXED 2026-09-18 (`WalkLegMinTicksFix`, user-confirmed; default on since 0.5.10)

- **Report:** arena Vajra, before `_climb_wall`, runs to a fixed wall spot and "runs on the
  spot" for seconds; the party member walking into an Akademeia teleport portal does the
  same. Log `ch4boss_run_20260917_234609` at 791.2–800.4 s: `_move_to_pit_start_pos`
  (target (0,-3483)) runs at mover speed 69.7 for 1.6 s, then from 793.0 s (850 units short)
  creeps at ~100 u/s for 7.4 s until the function's final `CMD1` snap.
- **Mechanism (BossProf/BossAI at 40 ms):** during the creep a walk leg starts (`ccc=1`,
  `cd6=0`, `vel`=(6.6,0,-18.9) = speed 20), lives exactly ONE rendered tick (`cd6=1`) and
  is ended (`ccc=0`, `cd4` shows the 0x20 "ended" code); ~4 renders later the next leg
  starts. The script loop is `while dist>=100 { CMD18(x,0,z); CMD61(_run_se_and_effect);
  CMDA(1); }` — `_run_se_and_effect` has no waits, so CMD18 is re-issued every native
  frame. `CMD18` (`0x14035D110`) stores the target in `+0xcac..+0xcb4` and starts state 1
  through the walk setter with the arrival-check bit; state 1 (`0x14019BCC0`) ends the
  leg when `0x1401B92C0` reports arrival at the nav waypoint, which here is true on the
  first tick (target beside the wall). Natively one tick = one 30-Hz step of 20 units;
  at 120 fps upstream scales the step to 30/fps, so each one-tick leg moves 5 units →
  a quarter of the native creep speed (100 vs ~600 u/s). Not the completion-event
  problem; the script itself was never stuck.
- **Candidate fix `[Movement] WalkLegMinTicksFix=1` (experimental, default 0):** at
  `0x14019BF4D` (unique signature `40 0F B6 C7 39 B3 CC 0C 00 00 74 1F 80 8B D4 0C 00 00 10`)
  the arrival kill is allowed only when `+0xcd6` ≥ round(fps/30); otherwise ZF is forced
  (`cmp esi, esi`) so the following `je` takes the "already idle" path. Budget kills and
  every other state are untouched. Effect: a re-issued one-tick leg lives 4 ticks = one
  native step per native frame. Built as MD5 `D0915CA22588C399A5EF56DEF22DE2B4`; deployed
  to the test PC at 01:10 with the switch on. Verify: the boss reaches the wall spot in ~1.5 s
  instead of ~7 s (BossPos creep speed), and the portal walk in Akademeia.

### Effect engine ("FunnyEffectsForPSP", Fec*) — chapter-5 turret white strobe FIXED in principle (2026-09-19)

**Turret fire-rate correction (Codex, 2026-09-19):** the older fire-rate notes
below misidentified projectile age as a shot counter and speed as charge.
`0x28e5b0` updates a single projectile: +0x86 age, +0xbc speed, +0xc4 acceleration,
+0xc0 speed cap. `0x49b180` submits transform command 0x10 for an existing effect.
Actual firing is in `0x2d2cf0`: if fire is held and dword `0x658ce8` is zero,
check resources (`0x195620`) then request action 0x500d (`0x193cf0`). The interval
is `(counter+1)%7` per render at `0x2d2e82..0x2d2e9c`, store at `0x2d2e9c`.
Old captures show 68 new projectile lifetimes at120FPS, predominantly 7 renders
apart, versus 28 at30FPS, predominantly 234–235 ms apart: genuine 4x firing.
`[Effects] TurretFireRateFix=1` replaces only that 26-byte arithmetic, period
round(7*fps/30); native <=30 untouched, exact233.333ms at60/90/120, other caps
within half a render. Default0 pending gameplay. `[Diagnostics] TraceTurretFire`
logs requests after the resource check in QPC ms, including native30.
Machine-code checks + Release build pass. One120FPS gameplay replay PASS (user
and log): 29 requests, 27 intervals of28 renders averaging233.403ms, one50-render
gap; no hook errors. Capture `dump/turret_test/success_20260919_152402/`, ASI MD5
`72A3E25ADCC0CE43315A603E79EC1C49`. Fix remains enabled on the test PC, trace disabled
after capture. Other caps not yet gameplay-tested; source default remains0.
See `TURRET_FIRE_RATE_HANDOFF.md` update and `docs/tools/test_turret_fire.py`.

- **Report:** chapter 5 mission 1 (Judecca turret vs dragons): each shot flashes the whole
  screen white at 120 fps, not at 30; also the mission banner before the video is short at
  120 (still open) and the turret fires visibly faster at 120 (open, see below).
- **Engine map (RTTI, `dump/image.bin`, base `0x7FF7ECD90000`):** 715 RTTI classes; effects
  are `Fec*` element classes of `FunnyEffectsForPSP` (particles, `FecAnm`/`FecAnm_plus`
  animated sprites, `FecMdl*` models, `FecFlash` full-screen flash, `Fec*_filter` screen
  filters, `FecCol/Colmv/Colac`, `FecPos*/Scl*/Rot*` modifiers, lens flares, lights).
  Class handler singletons live in the table `0x631780[type]`; vtable slot 1 (+8) =
  modifier evaluate `(handler, ctx, def, state, state, prev, float t)`, slot 3 (+0x18) =
  draw `(handler, ctx, def, r9, state)`. Draw loop: two clones `0x1404A8DEA` /
  `0x1404AA09C` (call at `0x1404A8E6B` / `0x1404AA11B`, signature
  `4C 89 44 24 20 49 8B D6 48 8B 01 4D 8B C2 FF 50 18 0F B6 45 15`). Update loop
  `0x1404A8980` → `0x1404A88D0` → `0x1404A81E0` (per-key modifier evaluation) and
  `0x1404A8760` (key advance). Vtables: FecFlash 570FB8 (draw 499580, colour → `0x76F470..7C`
  clamped to 255), FecAnm_plus 570B08 (draw 4CCF80), FecGaussian_filter 570A18,
  FecMonochrome_filter 570928, FecColmv 571E18, FecColac 571D28, FecPosmv 572188 (full list
  via `docs/tools/find_field_refs.py`-style RTTI scan in the session log).
- **Element clock:** `[element+0x40]` float, advanced 30/fps per rendered frame (the FecFlash
  alpha ramp reached 255 in 0.32 s at both 30 and 120 fps). Modifiers are evaluated at
  `(int)clock` (`movd xmm3, esi; cvtdq2ps` in `0x1404A81E0`; keys start at `short[key+4]`).
  Draw context `+0xe8` = element, `+0xf0` = current key, `+0xe0` = scale block.
- **Root cause of the strobe:** a new element is drawn at clock 0.25/0.5/0.75 (key 0) before
  its first native frame; at 30 fps the first draw is at clock 1, so key 0 is never shown.
  The turret muzzle `FecAnm_plus` sprites' key 0 is a screen-filling white burst. Proof:
  hiding the first 3 renders of each sprite instance (`FecSkipFirstRenders=3`, build
  `D355DAE8`) removed the strobe with the rest of the shot effect intact (user, 120 fps).
  Hiding classes by hotkey showed the whole shot effect lives in `FecAnm_plus`; `FecFlash`
  (black, alpha→255, identical at 30/120) and the Gaussian/Monochrome filters were not it.
- **Fix `[Effects] FirstFrameFix=1`** (experimental, default 0, >30 fps only) — FINAL RULE
  (user-verified 2026-09-19: no strobe in the turret, title screen and party menu clean):
  in the draw-loop hook, a sprite INSTANCE (runtime-state pointer = 5th draw argument;
  pool slots are reused, a gap > 8 renders counts as a new instance) is not drawn during
  its first round(fps/30)-1 rendered frames, and only for the sprite classes FecAnm_plus
  (570B08), FecAnm (571F08), FecMegaanm_plus (570B58). Two rejected variants: hiding by
  element clock `0 < [element+0x40] < 1` (the muzzle effect is a looping element whose
  clock never drops below 1 → strobe stayed; looped title-screen sprites blinked every
  cycle), and applying it to all classes (filter elements such as FecGaussian_filter build
  the blurred menu background; hiding their first frames left the party-menu background
  as an uninitialised texture). Original wording of the mechanism kept below. Same timing as native (first visible
  frame 33 ms after spawn). Possible side effect: looping elements that wrap to clock < 1
  blink for 3 renders per loop — not observed yet. Build `B9F2C57F2C41A8B785E1896F4CEE1B53`,
  NOT yet deployed (the test PC off). Diagnostics kept: `TraceFecDraw` (per-frame class histogram,
  hotkeys 1-7/0 hide classes, `FecSkipClass`, `FecSkipFirstRenders`), `TraceFecFlash`,
  `TraceFecAnm`, `FlashScan` (8/9 keys), `WriteWatchRva`.
- **Turret fire rate — TWO frame-rate faults, both fixed (2026-09-19):**
  (a) The shot's sound/muzzle is a keyframe event of the fire clip; the animation event-track
  player `0x1403BD780` dispatched it on every render while the integer clip frame sat in the
  event window, firing it fps/30 times — `[Effects] EventOncePerFrameFix=1` routes every layer
  rate through the game's own once-per-integer-frame walk (two `jb`→`jmp` at `0x1403BD7E2/EB`).
  Verified: it removed the duplicate sounds (one per shot, no more 1-render pairs). But the
  SHOT CADENCE was unchanged because of (b).
  (b) The weapon state machine `0x14028E5B0` (per weapon slot at `[0x658C00]+slot*0x130`, phase
  `[slot+0x7a]`) runs per RENDERED frame. Its fire "charge" accumulates
  `[slot+0xbc] = clamp([slot+0xbc] + [slot+0xc4], [slot+0xc0])` each call (site `0x14028F886`);
  when the shot counter `[slot+0x86]` reaches `[slot+0x88]` it fires and resets. So the charge
  fills fps/30 times too fast → ~4x fire rate at 120 (`[SndNew]` path `+28E698 +263B8E`: 96
  sounds at 120 vs 26 at 30 over a comparable window; the anim-event sound path was equal at
  330 ms). Fix `[Effects] WeaponChargeRateFix=1` (experimental, default 0, >30 fps): scale the
  per-call increment `[slot+0xc4]` by 30/fps at all five identical charge sites
  (`0x28CAB7/28F886/29012A/29F9E1/2B1463`, signature
  `F3 0F 10 87 C4 00 00 00 F3 0F 10 8F C0 00 00 00 F3 0F 58 87 BC 00 00 00`, replace the
  8-byte `movss xmm0,[rdi+0xc4]` with load+`mulss xmm0,%0`). Applies to every weapon slot
  (enemies/player guns too — the same render-driven charge), so watch other weapons' cadence.
  Build `97625E08`, deployed to the test PCs with EventOncePerFrameFix. Diagnostics
  `TraceSoundNew`/`TraceAnimRate` still on.
- **Turret fire rate (old note):** `[SndNew]` stacks (manual
  `RtlVirtualUnwind` from the hooked ctor entry; `RtlCaptureStackBackTrace` stops at the
  trampoline) show every shot sound coming from the animation event-track player
  `0x1403BD780` → event dispatcher `0x140261370` → SE play `0x1DCFF0/0x1E0108`: the shot is a
  keyframe event of the turret's fire clip. Cadence at 120 fps: sound pairs 1 render apart,
  shots every 37-38 renders. The player dispatches events while the layer's INTEGER frame
  (`[layer+0x6c]>>8`) is inside `[startFrame, endFrame]`; for |rate| <= 1 it dispatches on
  EVERY call (assumes one frame per call), for |rate| > 1 it walks `[layer+0x70]` (last
  processed frame) up to the current frame once per frame. At 30/fps rates the same integer
  frame repeats fps/30 renders, so a one-frame event fires fps/30 times (turret: several
  shots/sounds/muzzle effects per animation frame; likely also the source of many "4x
  triggers" upstream dedups per handler). Fix `[Effects] EventOncePerFrameFix=1`
  (experimental, default 0, >30 fps): the two `jb` at `0x1403BD7E2/EB` (signature
  `0F 2F C1 72 5A 0F 2F 0D ? ? ? ? 72 51 85 D2 7E 44`, bytes +3/+0xC → `EB`) send every rate
  through the walking branch. Assumes `+0x70` is reset when a clip (re)starts, as the
  game's own >1 path already requires. Verify: shot cadence at 120 equals 30 fps; watch for
  missed events elsewhere (attack hits, footsteps).
- **Open — turret fire rate (old note):** shots at 120 fps are audibly faster than at 30 (sound
  instances ~8.4/s from the `RootSound` ctor `0x14009DBA0`, counter `0x65ECF8`). Next:
  `[Diagnostics] TraceSoundNew=1` logs the ctor's caller stack (`[SndNew]`) → find the turret
  fire routine and its reload counter (likely a per-render countdown like the other `frint`
  patches). Mission banner: `MissionStartState` is the mission-select menu, not it; candidates
  `LoadingScreen` (vtable 56C1C8) or a screen-layer command; FlashScan around the banner
  showed only 30 Hz counters (5 s window) — the banner phase may run its own 30 Hz loop.

### Field save stone "jerks at the end of each spin" — FIXED (2026-09-22, `[Effects] AnimLoopSeamFix`; superseded 2026-09-26 by `AnimQuatAlignFix`, which aligns after every key, see "Character animations 1.56% slow")

- **Report:** the field save point rotates smoothly at 120 fps at the right speed but hitches once
  per revolution ("дёргается в конце оборота"). Present since the first high-fps sessions (parked as
  "save-stone flicker").
- **Not the effect engine:** hiding every drawable Fec class by hotkey (`TraceFecDraw` keys 1–7) left
  the stone untouched. `TraceLoopWrap` (new `[Diagnostics]` key, default 0; logs effect element loop
  wraps + clocks, FecRotmv updates and animation layers near their loop boundary with root yaw / bone
  quaternion cur/prev/out) showed effect loop clocks wrap cleanly (29.75 → 0.0) and found two looping
  animation layers: the player's idle (ch 0, 80 keys) and **the stone = actor channel 9, class word
  0x0000, 2 bones, a 45-key clip on bone 1 = a 360° spin about Y in 8° steps** (`ini_*` logs
  `dump/savestone_run{1,2,3}_2026092*.log`). Its frame counter is continuous across the wrap.
- **Root cause (sampler, not the step):** key 44 = (0, −2240, 0, **−32690**) and key 0 = (0, 0, 0,
  **+32767**) are the same rotation with opposite quaternion sign (a full turn ends at −identity). At
  the wrap the cursor rewinds to key 0 while `prev` stays key 44, and the sampler's 16-bit lerp runs
  straight through w = 0 — a 180° flip spread over the fps/30−1 fractional renders of the last interval
  (traced w: −29367 → −13258 → +2851 → +18959). At 30 fps frac is always 0, so the lerp never runs and
  the seam is invisible. The game's hemisphere alignment `0x1403BEA50` would fix exactly this but is
  gated on layer flag 4, which neither the stone's nor the party's layers carry.
- **Fix `[Effects] AnimLoopSeamFix=1`** (default 0, >30 fps only; the test PC on): one byte at `0x1403BEBF3`
  (`test byte ptr [rcx+0x84], 4` → `0xC`, signature `F6 81 84 00 00 00 04 74 05 E8`) so the alignment
  also runs after a rewind of a looping layer. Verified 120 fps (`dump/savestone_fixed_20260922.log`):
  after the wrap `prev` = (0, +2240, 0, +32690), output y 2126 → 1575 → 1023 → 472 → −79 → −630, w
  stays 32690..32767; user: stone spins without a hitch, no side effects while running around.
  No-op for loops whose adjacent keys share a hemisphere (dot > 0), which is every normal idle loop.
- **Effect engine facts gathered on the way** (FunnyEffectsForPSP, see also "Effect engine" above):
  the per-render effect step is `xmm6 · [effect+0x1f8]` at `0x1404AA238` — upstream's "Cycling 2d
  elements speed" patch (`48 8B CB 75 0D 0F 28 D6 F3 0F 59 90 F8 01 00 00`, comment `[ref: 0x002E4E50]`
  is stale) replaces that multiply with `·30/fps`, so the element clock advances 0.25/render at 120
  and effect `+0x13c` (this render's delta) / `+0x138` (total time) follow it; sprite-sheet cell
  animation (FecAnm_plus slot 2 `0x1404CCE10`) uses `+0x13c`, so it is time-correct. Element loop:
  flag 0x10 set in `0x1404A97C0` when clock ≥ `word[def+0xe]`, wrap `0x1404A88D0` = keys advanced to
  end−1, listed modifiers re-initialised at the loop start (`0x1404A81E0`, slot 5), clock = start +
  overshoot % length + fraction. Handler vtable slots: 0 init, 1 evaluate at key, 2 per-render update
  (t = clock − key start, fractional), 3 draw, 5 loop re-init, 7 apply. Continuous modifiers (FecRotmv
  `0x572138`: state `+0..8` out, `+0x10..` base, `+0x20..` velocity, out = base + vel·t) are therefore
  smooth at 120. Class → vtable RVA map from RTTI: FecMdl_plus 570A68, FecMdlts_plus 570AB8, FecAnm_plus
  570B08, FecMegaanm_plus 570B58, FecFlash 570FB8, FecColmv 571E18, FecAnm 571F08, FecMdl 571F58,
  FecSclmv 571FA8, FecRotac 572048, FecRot 5720E8, FecRotmv 572138, FecPosmv 572188, FecPos 572228
  (full list: `.?AVFec*@FunnyEffectsForPSP@@` type descriptors → COL → vtable).

### KNOWN UNFIXED frame-rate bugs (chapter 5, deferred 2026-09-19)

Two remaining >30 fps bugs the user chose to leave for now (session closed while playing):

- **Chapter-5 turret: FIXED, one120FPS gameplay replay confirmed.** Local modulo-7
  counter in `0x2d2cf0` was unscaled; see correction above. The apparent contradiction
  was projectile age being mistaken for shot count. `TurretFireRateFix` scales this
  counter's period; both older unsuccessful experiments remain off by default.
- **Chapter-5 (and general) mission-start banner is too short at 120 fps.** The still image
  with the mission title shown before the intro video flashes past faster than at 30 fps.
  Not investigated beyond ruling out `MissionStartState` (that class is the mission-select
  menu). Candidates: `LoadingScreen` (vtable `0x56C1C8`) or a screen-layer hold command with a
  per-rendered-frame countdown (same family as the `frint`/CMDA/script-layer-wait counters
  already scaled). Likely a one-line 30/fps scale once the counter is found.

### Lock-on camera (verified 2026-09-05)### Lock-on camera (verified 2026-09-05)
- **2026-09-22: the 0.5.4 soft-follow hook (`LockFollowPercent`/`LockDeadZoneDegrees`, site `0x1402f278a`)
  was removed from the mod, the tuner and the INI after a Nexus user confirmed it does nothing in normal
  lock-on (the site only runs in camera mode 4). The working smoothing is `LockTurnMaxDegPerSec` +
  `LockTurnDeadZoneDegrees` further below. Historical notes on the old hook follow.**
- Camera update function `0x1402f1ef0`; lock-on branch runs when `[0x658f48] == 4`. The stock code has
  NO smoothing: each frame it computes the yaw error to the target and applies it fully (instant snap),
  which is why the camera whips when an enemy circles the player.
- Patched site `0x1402f278a` (signature `F3 0F 10 4C 24 30 41 0F 28 C1 41 0F 47 C0 F3 41 0F 58 CC`,
  19 bytes): error `e` (xmm1) becomes `sign(e) * max(|e| - dead, 0) * gain`, with `dead` in radians and
  `gain = 1 - (1 - p)^(30/fps)` recomputed by the camera watcher so the feel is fps-independent
  (`p = LockFollowPercent/100`, `p >= 1` → gain 1 = stock).
- **Close-range whip is NOT the yaw step above (2026-09-18).** `[Diagnostics] TraceCamera=1`
  (look-at `0x725168/6c/70`, previous look-at `0x74f0b8/bc/c0`, eye caches `0x7268a0/0x726890`
  — these two are the player's eye point, not the camera —, player/target mover positions,
  every 16 ms while `[0x658D30] >= 0`) showed: during normal lock-on `[0x658f48]` stays 0
  (not 4); `0x725168` always equals `0x74f0b8`, i.e. the yaw commit path is not what moves
  the view; the look direction swung ~220° in 0.25 s the LONG way round while the enemy's
  bearing changed ~40°. Turn rates: 120 fps max 1548 deg/s (p95 850); native 30 fps max
  1988 (p95 1097) — same or faster, so it is stock behaviour, not a frame-rate bug. The
  view is driven by the camera mover `0x1402f0120(actor, lookPoint, dist, dist2, ch)`
  called twice at the end of `0x1402f1ef0`; lookPoint = the locked enemy's position
  when its flag `+0x9f2` bit 0 is set. Mover outputs: look-at `0x7267c0/c4/c8`, camera
  position `0x7267d0/d4/d8`. `DAT_140611bbc` (=1.0) scales the transition frame counts
  (2..40) in that function; writers `0x1402EC4FC`, `0x14035069F`.
- **Fix `[Camera] LockTurnMaxDegPerSec`** (0 = off, live in the tuner, default 0): both mover
  calls (`C6 05 1B 6C 36 00 00 89 44 24 20 E8 6D DB FF FF` at `0x1402f25a3`, 11 bytes, and
  `49 8B CD 89 44 24 20 E8 EE CE FF FF` at `0x1402f3226`, 7 bytes) get `rdx` replaced by
  `SmoothLockLookTarget(actor, point)`: a point at the enemy's radius/height whose bearing
  from the player moves at most limit/fps per rendered frame (snap on first use or when
  the real point jumps > 3·radius+3000). Bridge saves xmm2/xmm3 (call args) and uses
  `xor r8d,r8d; mov byte [rip+?0], r8b` to re-emit the replaced rip-relative store.
  First test build MD5 `7EB7B794619597605015DADEF4EC9C97`, the test PC ini 180 deg/s.
- **Result (2026-09-18 night):** the input-point substitution alone did NOT cap the view
  (trace: still 700-1300 deg/s) because the mover reads the target again itself
  (`0x1402f0611`, rbx = player = param_1, r13 = target; the first read at `0x1402f0603`
  is the PLAYER into [rbp+0x10], the target goes to [rbp-0x28]). Hooking after the
  second read (`FF 50 28 F3 0F 10 45 18 F3 0F 10 55 10 F3 0F 10 75 14`, offset 3, 10 bytes)
  and rewriting the target buffer with the shared point (advanced in real time via QPC,
  loose-framing zone re-centres at 1/4 speed) works: build `65A1965F81E9FF3A8483861E9F6084B4`.
  A first version hooked after the player read and aimed the camera away from the enemy.
  User verdict: whip gone, camera smoother; running circles around an adjacent enemy still
  turns the view fast because the player's own bearing change is what the camera follows.
  Left as is with the user's tuner values `LockTurnMaxDegPerSec=121`,
  `LockTurnDeadZoneDegrees=35` (old `LockFollowPercent/LockDeadZoneDegrees` are inert on
  this path). Not in a release yet; default 0. Ideas not done: inertia (ease-in/out),
  pulling the camera back at close range, framing the midpoint instead of the enemy.
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
  frame 24.8 at `+0x6c`, last processed `+0x70`, rate `+0x74` (the mod sets 30.1/fps since 2026-09-26, was 29.9/fps),
  loop start `+0x78` (float), length `+0x7c`, flags `+0x84` (bit 0 playing, bit 1 = 2 just (re)started,
  bit 2 = 4 "sign-align quaternions after a rewind" (see below), bit 3 = 8 loop), loop count `+0x80`,
  byte `+0x82` = 1 → root tracks not linked (no root motion), clip `+0x8`, track array `+0x18`.
  Step `0x1403BDB60`: `frame += (int)(rate·256)`; non-loop finishes when frame > (len−1)·256 and
  clamps; loop wraps `frame -= (len − start)·256` when frame ≥ len·256 (fraction preserved, verified
  79.98 → 0.23 at 120 fps). At 30 fps the last frame is dispatched twice, at 120 once.
  **Pose sampler `0x1403BEB50`** (per layer, called from `0x1403BFE10` after the step): cursor key =
  `ceil(frame)` (`(frame + 0xff) >> 8`); if ≥ len: loop → `start + (key − len)`, else `len − 1`. A
  cursor moving backwards rewinds the tracks (`0x1403BEDD0`: stream pointer reset, `prev = saved cur`,
  then one key decoded); forwards it advances N keys (`0x1403BEE60`, RLE/delta byte stream per
  track, `+0x22` repeat count, `+0x30` read pointer, `+0x40` last delta). Each track (0x58 bytes):
  `+0x42` value at the cursor key, `+0x44` value at the key before, `+0x48` output =
  `prev + (cur − prev)·(frame & 0xff)/256` (16-bit lerp; with frac 0 = cur), `+0x1c` float scale,
  `[+0]` target float. Track array (clip binder `0x1403BE260`): 10 root tracks (0-2 position, **3 = root
  yaw in turns, 0x8000 = one turn**, shortest-path wrap by ±0x7fff applied inline when |cur−prev| >
  0x4000 and `+0x82 == 0`), then bones from `+0x370`, 7 tracks each (0-3 quaternion xyzw in 1/32768,
  4-6 position); bone count `word[container+0x44c]`. `0x1403BEA50(layer)` negates a bone's four
  `prev` components when `dot(prev, cur) < 0` (quaternion hemisphere alignment) and is called after a
  rewind only when flag 4 is set. The lerp path is never exercised at 30 fps (frac always 0).
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

### Weapon stance and dodge speed — FIXED at 120 FPS (verified 2026-09-16)

**Resolution:** the reported excessive dodge acceleration at high FPS is fixed and
accepted by the user after the final the test PC test. Enable all three `[Movement]`
switches: `MotionStartWaitFix=1`, `ScriptWaitFrameFix=1`, `DodgeCadenceFix=1`.
The reference is native 30 FPS at maximum tier 3 (`cap=2`), not equal speeds in
both stances. Native running is 20% faster with the weapon drawn; native repeated
dodges have nearly equal range but 400/300 ms unarmed/armed cadence. Preserve both
differences. Using an ability exposed the stance change; it was not a separate
ability-specific speed multiplier, nor an L3/analog-cap defect.

Four high-FPS timing effects were isolated: CMD134's two-render-frame setup wait,
CMDA Wait(1) returning on the next render, truncation of the 29.9/fps animation
step, and next-render consumption of repeat permission. The combined fixes restore
native setup time, polling, animation eligibility frames and repeat latency.
Final 120 FPS medians are 400.035/299.984 ms with native-equivalent range (full
measurements below). Lip-sync correction is retained outside gameplay dodges.
(2026-09-26: the "lip-sync correction" 29.9/fps is gone; CharAnimRateFix uses 30.1/fps = the exact step for
every motion, and the lips are kept right by AnimQuatAlignFix. DodgeCadenceFix's exact-rate exception is
now integer-redundant at 60/120.)
This closes the reported bug for the tested scenario; experimental defaults and
broader regression coverage are separate from that result. The investigation below
is chronological: intermediate failures are retained as evidence, not open blockers.

- Drawing the weapon reproduces the reported speed change without using an ability;
  sheathing it reverses the change. Runtime on controlled ch0 (class `0x000D`): actor
  `+0x878` changes `00` / `0A`, and bit `0x80` of `+0x6b8` follows the stance.
- The captured `remu` script explicitly sets `run` to 26 and `battle_run` to
  `26 * 1.2 = 31.2` through the shared `BtlSetMoveSpeed` function. At the top L3
  tier (`cap=2`, displayed level 3), these become 52 / 62.4. The shared setter's
  CMD16 ends at PC `0x822A`; that PC in `[Param]` is the command's end, not its start.
  This 20% difference is authored in the game script, not introduced by analog tiers.
- `avoid` sets speed 26 in both stances, but selects different motion IDs (70 / 2085)
  using CMD140. Do not equate the 20% run-speed difference with dodge speed, or use
  mover `+0x78` alone: it is zero during the observed animation-driven dodges.
- the test PC control at **30 FPS**, analog enabled, `cap=2`, dash multiplier `+0x2a8=9.6`:
  three consecutive unarmed dodge cycles covered 708.55 / 708.28 / 708.55 world units
  in 390 / 406 / 407 ms; two armed cycles covered 705.09 / 709.59 units in 313 / 297 ms.
  Thus the native-rate test already has roughly equal range and a shorter armed cycle
  (~0.3 vs ~0.4 s, ~33% faster average traversal). Boundaries are approximate: telemetry
  samples every 100 ms. These are cycle intervals, not exact animation clip lengths.
- At 120 FPS a separate run with turns/wall contacts had median start intervals
  312 / 204 ms. Different input paths and coarse sampling prevent treating that as an
  exact 30-vs-120 comparison. This early trace did not establish correct timing.
  Actor `+0x5d8` stayed 0.249167 at 120 FPS and 1 at 30 FPS across both stances.
- A later straight 120 FPS run (`straight120_20260916_222725.log`) also shows
  apparent request intervals near 0.30 s unarmed and 0.20-0.22 s armed, versus
  ~0.40/~0.30 s at 30 FPS. These are preliminary: `[Param]` timestamps are assigned
  when the watcher DRAINS the ring every 100 ms, not when the command executes.
  Do not use their medians as precise cooldown measurements or pair them with
  `[MoveState]` positions as exact per-dodge boundaries.
- CMD134 (`0x140351d60`) stops ordinary movement on its first call, then increments
  context `+0x4c` by 1 and yields while it is below 2. Only the subsequent call
  queues the motion via `0x14034edb0` and sets actor `+0x5d4` from global m3.
  This two-rendered-frame wait was unscaled before MotionStartWaitFix; precise
  measurements below isolate its contribution. CMD140 (`0x1403528f0`) returns actor
  `+0x6b8` bit 0x80. CMD17F (`0x140355110`) calls `0x140274880`, which checks animation
  event words and action queues to decide cancellation; it is not a simple cooldown.
- `TraceMove` also wraps CMD134/CMD17F through validated VM-table entries, preserving
  original calls/results. `[MoveCmd <ms>]` uses QPC captured on the game thread
  (milliseconds since hook installation), with request/wait/start/cancel phases,
  motion ID, position, stance, and actor `+0x5d4/+0x5d8`. This works at 30 and 120 FPS;
  its clock origin differs from `[MoveState +ms]`. These diagnostic wrappers do
  not themselves change gameplay.
- Precise 120 FPS test (`precise120_20260916_223901.log`, two series per stance):
  start-to-start medians are **333.45 ms unarmed / 233.38 ms armed** (14 intervals
  each, excluding gaps between series). Straight interior cycles cover ~689.11 /
  ~692.52 units: armed traversal is ~43.5% faster, not 2x. Initial cycles include
  turns/contact and are shorter; do not interpret their displacement as full range.
  CMD134 request-to-start medians are 16.48 / 16.49 ms (two frames at 120 FPS).
  At each motion start `+0x5d4=2` and `+0x5d8=0.249167` in BOTH stances; before the
  request `+0x5d4` is 1 unarmed / 1.1 armed, overwritten by CMD134's m3 assignment.
  Consecutive repeats generally occur without a positive CMD17F return.
- Precise 30 FPS control (`precise30_20260916_224305.log`): start intervals
  **399.98 / 299.98 ms**, straight cycle distances ~708.55 / ~709.59 units;
  setup waits **66.46 / 66.04 ms**. Motion rate `+0x5d4=2` in both stances,
  actor rate `+0x5d8=1`. This confirms ~50 ms of the ~66.6 ms high-FPS cycle
  reduction is the unscaled CMD134 setup wait. It does not explain the remaining
  timing/range difference. Native armed series are ~33.5% faster on this actor.
- Test fix `[Movement] MotionStartWaitFix=1` (experimental, default 0): change
  CMD134's setup threshold from 2 to `2*fps/30`, retaining its +1 counter and
  original initialisation/queue behaviour. At `0x140351ee1`, replace the single
  8-byte `movss xmm0,[2.0]` with a load of a private scaled constant; do not edit
  the shared 2.0 cell. Applies to all users of CMD134, so combat/motion transitions
  also need regression testing. No high-FPS patch is installed at FpsCap=30.
  First 120 FPS verification below is partial; do not call all movement solved.
- With MotionStartWaitFix (`waitfix120_20260916_224954.log`), setup waits match
  30 FPS (~66 ms). Armed cycles now match **300 ms**, and straight interior cycles
  cover ~709.08 units versus 709.59 at 30 FPS. Unarmed cycles still run at
  **366.7 ms** versus 400 ms and cover ~692 units on the cleaner intervals.
  Many later intervals contain turns/actions; only compare straight segments.
  The user reports improved pacing and explicitly wants native 30 FPS behaviour
  at 120 FPS, even where this makes combat harder.
- Another independently verified defect: CMDA Wait(N), handler `0x14035c910`,
  tests remaining time BEFORE decrementing context `+0x38`. The upstream dedup
  subtracts a whole 1 on its first touch, so Wait(1) immediately reaches zero and
  can return next rendered frame (8.33 ms at 120 FPS, versus 33.33 ms natively).
  Waiting one frame occurs before/in the dodge's motion-completion polling loop.
  Test `[Movement] ScriptWaitFrameFix=1` (experimental, default 0) replaces ONLY
  CMDA's old dedup subtraction with `30/fps`, snapping <=1e-5 residuals to zero
  while preserving NaN. It does not gate the VM or change script variables.
  Installed in the existing `!DisableCounterDedup` block. Byte-exact unique site:
  `0x14035c921`, 8-byte `subss xmm1,[1.0]`; same hook boundaries as upstream.
  SSE float32 simulation: waits 0/1/2/7/30/60/600 at 30/60/90/120/144/240 FPS are
  never shorter than their authored duration and at most one rendered frame late;
  binary steps (30/60/120/240) match exactly. Long waits/cutscenes also need
  regression coverage.
- Both fixes at 120 FPS (`bothfix120_20260916_225620.log`): unarmed start intervals
  ~375 ms, straight range ~697.85; armed ~308.36 ms, range ~711.16. Neither is an
  exact match to native 400/300 ms. The fractional wait fixes a real short-wait
  defect but does NOT finish the dodge investigation; avoid compensating with
  arbitrary stance-specific speed/cooldown constants.
- Completion diagnostics now wrap CMDFC (`0x140364490`) while a CMD134 motion is
  active: `[MoveCmd] phase=poll/finished` records its result, actor motion request
  count `+0x6d0`, current motion `+0x5c8`, and animation layer 0 frame/length/rate/flags.
  CMDFC calls `0x1401b45c0`, which runs `0x1401b49a0` and tests whether the request
  is still in the motion queue. Queue removal depends on virtual animation state
  getters (+0x260/+0x268) and loop-count changes (+0x250), not just elapsed time.
  Static animation layout: `0x1403addf0(this=mover+0xb0)` calls `0x1403bfd70` at
  this+0x4e0 = mover+0x590; layer 0 is container+8. The trace validates the layer's
  container backpointer and container+0x478 owner == actor before reading fields;
  animFrame=-1 means validation failed. At FpsCap=30 both experimental timing
  patches are skipped; the native trace below establishes the comparison baseline.
- Native completion trace (`completion30_20260916_231833.log`) validates the layer
  layout. It reproduces 399.99/299.98 ms cycles and ~708.55/~709.59 range. Unarmed
  clip 2085 has length 34; armed clip 70 length 35. Layer rate changes from 1 at
  the queue/start trace to 2 on the next frame, then advances 512 fixed-point units
  (=2 animation frames) per 30 FPS tick. Crucially, repeated dodge requests occur
  at **old clip frame 20 unarmed / 14 armed**, while the request queue still has
  one item and CMDFC previously returned 0. These are action interruptions before
  clip completion, not waits for the clip's final frame. No `finished` trace occurs
  in these series; positive CMD17F cancel appears when the series stops (e.g.
  unarmed frame 20, armed frame 22), not for every repeat. Compare the 120 FPS
  repeat-eligibility points below; the remaining error was not clip-end dwell.
- 120 FPS completion trace (`completion120_20260916_232119.log`, both prior fixes):
  requests repeat at fixed-point frame **4699/256 = 18.3555** unarmed and
  **3683/256 = 14.3867** armed, matching 375/308.38 ms cycles. CMDFC polls every
  ~33.33 ms at frames 508,1016,...: 29.9/fps gives layer rate 0.498333, truncated
  to 127/256 per render (508/256 per native tick, instead of exactly 2 frames).
  Last polls before repeat are 4572/256=17.8594 and 3556/256=13.8906 respectively;
  next request occurs one rendered frame later. Native last polls are frame 18/12,
  with the next request one native frame later at 20/14. Thus two effects interact:
  animation rounding can miss an eligibility window at a poll, and consuming the
  permission on the next render has 8.33 ms latency instead of native 33.33 ms.
- Static consumer identified: `0x1402d9af0(actor, ai)` checks AI `+0x48` bit 0x4000
  before requesting dodge action 0x5001 through `0x140193cf0`. CMD17F's helper
  `0x140274880` sets this bit from event `+0x1a0` bit 15 (unless `+0x48` bit 18).
  The actor animation-rate assignment at **0x140191647** is a PER-FRAME reset
  at the end of `0x140191510`, not a constructor-only assignment.
- Test `[Movement] DodgeCadenceFix=1` (experimental, default 0) complements the
  two wait fixes: the per-frame reset uses exact 30/fps during party action 0x5001
  in gameplay (gameMode 0, no actor cutscene gate), retaining the lip-sync nudge
  elsewhere. A hook at `0x1402d9af0` delays consuming newly observed permission by
  `ceil(fps/30)-1` additional rendered frames, only while the controlled actor is
  already dodging. State resets when permission clears, the actor/request changes,
  or it leaves that action. Initial dodges/ordinary steering/VM ticks are not gated.
  At 120 FPS the intended reaction is 8.33+25=33.33 ms; no stance-specific cooldown
  constants are used. Both hook signatures/boundaries and keystone short branches
  verified; build/deploy completed, runtime verification below.
- Implementation details needed to maintain the fix: the action queue has capacity
  at actor `+0x7b8`, head at `+0x7bc`, count at `+0x7c0`, and entries at `+0x7c4`
  with stride `0x28`; current entry is `(head % capacity)`, action ID is its word
  `+4`. The rate exception requires party channel 0..2, gameMode 0, actor `+0x965=0`
  and action `0x5001`. Permission-delay state is per party channel and keyed by
  actor pointer/request ID at `+0x40`, using the rendered-frame counter; only the
  controlled actor's repeat input is delayed. The animation reset hook replaces
  the complete 10-byte store at `0x140191647`; the input hook replaces the 7-byte
  prologue of `0x1402d9af0`, preserving its two argument registers and Win64 stack
  alignment/shadow space. At 120 FPS, exact actor rate 0.25 and motion rate 2 yield
  128/256 animation frames per render, versus truncated 127/256 with 29.9/fps.
- the test PC runtime verification (`cadence120_20260916_233454.log`, tier 3, all three
  fixes enabled; ASI MD5 `71784CE8814CEA62EBF7F0E8DB6B47B7`): unarmed median
  **400.035 ms** (14 repeat intervals), armed **299.984 ms** (16), matching native
  **399.988/299.976 ms**. One unarmed interval was 408.048 ms (one extra rendered
  frame); the remaining intervals cluster around 400/300 ms. Straight interior
  displacement is **708.54-708.55 / 709.54** units versus native **708.55 / 709.59**;
  armed difference is about 0.006%. Repeated requests now occur at exact animation
  frames **20 / 14**, matching native. Actor rate during dodges is 0.25, layer rate
  0.5; initial requests outside dodge retain 0.249167, confirming the lip-sync
  nudge is not globally removed. Actual cutscene/lip-sync playback was not tested.
  This verifies the recorded character/tier-3/120-FPS scenario; other characters,
  tiers, FPS caps and broader script-wait/cutscene regressions remain untested.
  Keep these switches experimental/default 0 pending broader coverage; the test PC has
  them explicitly enabled. The native armed/unarmed cadence difference is preserved.
- `[Diagnostics] TraceMove=1` now adds `[MoveState]` at 100 ms: position, mover delta,
  actor motion field (not reliable for this character), stance/movement flags, actor
  animation rate and game mode. The trace window is 15 minutes after actor appearance.
  Raw logs and offline decoding/analysis are in local `dump/speed_ability_test/`.

### MP restoration while holding an ability — fourfold acceleration FIXED (2026-09-17)

**Resolution:** `MpRegenFix=1` removes the fourfold MP gain at 120 FPS while
preserving the native gauge drain. Latest verified rate: 58.289 MP/s versus 58.174 at
30 FPS, instead of the broken 233.299. The user reports that it appears to work.
The first implementation lost one final grant when the gauge emptied; the verified
first-observation revision instead ends one grant ahead of native (~6 MP), matching
the user's explicit preference for a small player-favourable residual difference.
Do not describe total restored MP as bit-exact.
The setting remains experimental/default 0,
explicitly enabled on the test PC alongside the dodge fixes.

- User reports roughly 4x faster MP recovery at 120 FPS and a full MP bar restored
  for about a quarter of the ability gauge, versus roughly the full gauge at 30 FPS.
  Exact ability/menu name is pending; runtime action is `0x5180`, ending in `0x5181`.
  Runtime verification of the fix is recorded after the native control below.
- Static resource helpers: `0x1401a7840` adds MP (`+0x940`, max `+0x944`),
  `0x1401a7900` adds ability gauge (`+0x948`, max `+0x94c`), and `0x1401a7700`
  adds HP. Deltas use units of 1/128 with signed-short remainders (`+0x9be`,
  `+0x9c0`, `+0x9bc` respectively); a nonzero third argument first makes the delta
  proportional to the maximum. Do not globally throttle these helpers: they are
  shared with other effects. Per-frame resource changes in `0x1401a0ee0` include
  MP drain `+0x9c4` and ability drain `+0x9c6 + +0x9c8`.
- Confirmed handler is effect update `0x1402a6cc0(index)`, effect table
  `[0x658c00] + index*0x130`: owner channel `+0x7c`, state `+0x7a`, counter `+0x86`,
  interval `+0x10c`. When counter modulo interval is zero it visits eligible party
  members and inlines a grant of maxMP/128 (preserving remainder) at `0x1402a7035`.
  It sets the owner's gauge cost `+0x9c6` from ability data byte `+0x23` while any
  MP is missing, and clears it when the owner leaves the corresponding action.
  Its `inc word [rbx+0x86]` is covered by the upstream 30-Hz counter patch, but
  the modulo/grant check still runs per render: a qualifying counter value may
  therefore grant four times at 120 FPS. Runtime attribution and the native
  30-FPS control below confirm the fourfold discrepancy.
- The existing patch labelled "Queen's Divine Judgement ability gauge's cost"
  at `0x1401a1823` actually scales the shared `+0x9c6 + +0x9c8` drain by 30/fps;
  it is not restricted to Queen. This can leave gauge drain correct while the
  candidate's MP grants repeat too often.
- Diagnostic ASI MD5 `CFADA3A0C866C2AD2B0DA4FEBA559161` deployed to the test PC at 120 FPS,
  retaining the three dodge fixes. `TraceMove=1` adds `[ResourceState]` every 100 ms
  (MP/AG/maxima/fractional remainders, costs, class, current action) and a count of
  visits to the candidate's grant-check block across all party targets. Its hook
  at `0x1402a701e` replaces one 7-byte `mov r9d,[rsi+0x944]`, preserving flags and
  registers; enabled also at 30 FPS. Build, unique signature, instruction boundary
  and keystone assembly verified; runtime application/attribution confirmed below.
  Analysis and backups are in `dump/mp_regen_test/` (gitignored).
- First 120-FPS trace (`regen120_20260916_235942.log`, class `0x000D`, controlled ch0):
  casting action `0x5209` reduces MP by 54 per cast, down to 98/746; holding action
  `0x5180` then restores MP to 746 while gauge falls from 100 to 69 in about 2.8 s.
  The candidate counter increases throughout this interval and stops afterward;
  no ASM FAIL/MISS/ABORTED reported. Regression over 26 active samples, including
  the 1/128 remainders, gives **233.299 MP/s** (31.273% of max/s), **11.252 AG/s**
  drained and **120.090 grant checks/s** across all party targets. Interior sample
  endpoints: 18.828 s -> 21.484 s, MP 121+40/128 -> 744+118/128, checks 12 -> 333;
  delta MP is exactly 107 * 746/128 while checks increase by 321, consistent with
  three target checks per grant cycle. Do not interpret the all-target check count
  as 120 grants per second to the controlled character. the test PC switched to FpsCap=30
  with the same diagnostic ASI for the next baseline; MP fix remains absent.
- Native 30-FPS control (`regen30_20260917_000402.log`, same class/ch0, max MP 746):
  **58.174 MP/s**, **11.241 AG/s** drain, **29.945 grant checks/s** across the party
  (85 active samples). Compared with 120 FPS, MP gain differs by 4.010x while gauge
  drain is effectively unchanged. From 98 MP the full gauge lasts about 8.9 s and
  MP reaches about 622/746; it does NOT completely fill MP in this particular setup.
  Do not tune the fix to the user's initial approximate full-bar description:
  measured native behaviour is the reference. Signed negative AG remainder at zero
  is possible in the native helper; it is not an actual negative visible gauge.
- Initial `[Movement] MpRegenFix=1` implementation (experimental, default 0) gates only the effect's
  modulo/grant branch with the SAME `propagatecounters` 30-Hz beat that advances
  its `+0x86` counter. At `0x1402a6f59`, replace the complete 8-byte TEST/JNZ;
  nonzero remainder OR a non-beat render goes to the original no-grant path at
  `0x1402a71f2`. The original counter increment (already patched) and action-exit
  cleanup still run through their usual paths. The gate covers all eligible party
  recipients and the cost update for that effect, preserving the authored grant
  amount/remainder; shared MP helpers, gauge drain, input and animation stay intact.
  RAX (dead quotient at this point) carries the absolute skip target. The diagnostic
  hook at `0x1402a701e` does not overlap this patch.
- Unique signature, both instruction boundaries, original branch target and
  counter-increment site verified against the dump; keystone emits 26 bytes with
  short conditional branches compatible with ParametricASMJump. Float32 clock
  simulation at 30/60/90/120/144/240 FPS, intervals 1/3/10 and initial phases 0/0.5
  confirms one grant opportunity per qualifying native counter value. At 120 FPS,
  interval 3 over 10 s changes 400 opportunities to the native 100. Release Win64
  build passes (existing warnings). the test PC now has FpsCap=120, MpRegenFix=1 and the
  three dodge fixes, ASI MD5 `5FA89411982557F39FB0998186A102A8`. Runtime result follows.
- Fixed 120-FPS trace (`fixed120_20260917_000925.log`, same class/ch0/action/max MP):
  hook enabled without ASM FAIL/MISS/ABORTED. Over 84 active samples the measured
  slopes are **58.267 MP/s**, **11.269 AG/s** drained and **29.993 grant checks/s**.
  Native comparison is 58.174 / 11.241 / 29.945 respectively: rates differ by only
  ~0.16% (MP) and ~0.25% (AG) in these sampled runs; the fourfold gain is gone.
  The action ends normally at empty gauge and cost resets to zero. Final MP is
  **616+90/128**, from initial 98, versus native **622+68/128**: 89 versus 90 grants,
  exactly one authored grant (`746/128 = 5.828125 MP`, 0.78125% of max MP) apart.
  This is an end-of-gauge boundary discrepancy, not residual faster steady recovery;
  its exact scheduling cause has not been isolated. Preserve this distinction if
  stricter tick-for-tick parity is investigated later. Other ability variants,
  characters, caps and interruption cases have not received runtime regression tests.
- User explicitly requested eliminating the final ~6 MP deficit, or biasing a
  remaining small discrepancy in the player's favour (2026-09-17). The revised
  `MpRegenFix` consumes each qualifying counter value on FIRST OBSERVATION rather
  than waiting for the global beat. The old gate could defer that value by up to
  three rendered frames at 120 FPS; the new run below verifies the final outcome,
  without isolating every scheduling contribution. Grant size and drain are
  unchanged; no arbitrary MP bonus or multiplier was added.
- `ConsumeMpRegenCounter(effect, owner)` remembers counter/owner pointer/owner
  request ID (`+0x40`)/action ID per effect address. Separate effects do not share
  consumption state; a new owner/request/action or counter permits a fresh grant.
  It runs only after the ORIGINAL modulo test succeeds, once for the whole party
  recipient loop. Hook site/skip target remain `0x1402a6f59` / `0x1402a71f2`.
  The helper call preserves RCX/RDX/R8-R11 and XMM0-XMM5, with Win64 aligned stack
  and shadow space; RAX was a dead quotient at that site. Native cleanup still runs
  every render. The existing `+0x86` increment remains at 30 Hz.
- Revised hook signature/boundaries verified; keystone emits 157 bytes with both
  conditional branches short. The actual C++ helper was extracted and compiled in
  `dump/mp_regen_test/first_counter_test.cpp`: tests pass for duplicate suppression,
  simultaneous effects, pool-slot reuse on a new request/owner, counter wrap and
  action change. Timeline checks at 30/60/90/120/144/240 FPS, intervals 1/3/10,
  phases 0/0.25/0.5/0.75 show every prefix has the same or one earlier grant than
  the old beat gate, never duplicates. These are not a game runtime proof of final
  resource parity. Release build passes; deployed ASI MD5
  `3AC7D42C554CB359037CF7F872072DFD`, the test PC FpsCap=120/MpRegenFix=1.
- First-observation runtime verification (`early120_20260917_002611.log`, same
  class/ch0/max MP 746): starts at MP 98, AG 100; ends at **628+46/128 MP**, AG 0,
  cost cleared and action `0x5181`. There are 273 target checks (91 grant cycles)
  versus native 270 (90). Native ends at **622+68/128 MP**: the difference is exactly
  **+5.828125 MP**, one grant (0.78125% of maximum MP) in the player's favour,
  as explicitly permitted by the user. The last sample of action `0x5180` already
  has native-equivalent MP 622+68/128 and zero visible AG; the extra grant appears
  in the transition to `0x5181`. Do not attribute that terminal grant specifically
  to counter advance versus request-identity reset without finer telemetry.
  Over 83 active samples: **58.289 MP/s**, **11.249 AG/s** drain, **30.004 checks/s**;
  the fourfold speedup remains absent. Hook enabled with no ASM FAIL/MISS/ABORTED.
  This verifies the requested no-deficit outcome for this scenario; broader
  character/variant/interruption/phase coverage is still limited as noted above.

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
   `cd6/cd8`, script op `0x179` layer wait, upstream-patched "various timings", the actor resource update
   `0x1401A0EE0` bytes/words `+0x5E6` hit-freeze, `+0x9B8`, `+0x9A9`, `+0x9A2` stun gauge, `+0x9DC` downed timer,
   `+0x9BA` (`ActorTimerFix`, 2026-10-31), status DoT ticks `+0xA98/+0xA9A` (unpatched).
2. **Shared mode-1 profile clock step**: scaling it scales servos too; and the reverse: a full-rate rule for
   a whole actor class makes its scripted turns fps/30 x fast (`EnemyTurnFullRate`, 2026-10-31).
3. **One-frame events vs 30 Hz consumers**: anything cleared per frame and polled per tick.
4. **Animation last-frame semantics**: rate 0.249 skips over the last integer frame.
5. **Flyer vertical motion per render** (gravity, hover servo, leg pushes, drag, and the Y position step in
   upstream's speed patch): fps/30 x fast for `+0xD9` flyers only; `BossVerticalFix` is incomplete (2026-10-31).
6. Party hit frequency and projectile reach on flying targets differ at 120 (unexplained,
   not currently a visible problem).

### Eidolon summon timer runs fps/30 x too fast — FIXED (2026-09-22, `[Effects] SummonTimerFix`)

- **Report:** upstream #20 "summon times are sped up"; measured by the user at 90 fps: the 2:00
  summon timer elapsed in 45 s (three summons, 46/47/46 s of Eidolon life).
- **Where the timer lives:** `word [actor+0x9b2]` of the Eidolon actor (which takes over the
  summoner's party channel 0..2; class word `0x0013`, HP 5242 for the tested Eidolon), in 30 Hz
  frames: initialised to 3600 by `0x14019F299` (copied from the party entry `+0xee` on restore),
  read by the HUD at `0x1402703BE` (`/30` via the 0x88888889 multiply) and mirrored back into the
  party entry `+0xee` at `0x1401A084B`. Found with the new `[Diagnostics] TraceSummon=1` (250 ms
  snapshots of the actor / AI block / battle+party globals / party entries while a party channel
  holds a class 0x10..0xFF actor; `docs/tools/summon_scan.py` lists monotonic fields). Same run
  also showed `0x658AB8` = a per-render battle frame counter (+90/s at 90 fps). HP was not the
  timer (discrete drops = hits).
- **Cause:** the per-render actor resource update (`0x1401A0FC5`, the function that also drains
  MP/AG) does `movsx eax,[rdi+0x9b2]; if ([rdi+0x11]==0 && [rdi+0x961]&4 && !([rdi+0x875]&1) &&
  eax>0) dec eax; mov [rdi+0x9b2],ax` once per RENDERED frame → −90/s at 90 fps.
- **Fix:** hook the 6-byte `test eax,eax; jle; dec eax` at `0x1401A1BAB` (signature
  `0F BF 87 B2 09 00 00 44 38 7F 11 75 14 F6 87 61 09 00 00 04 74 0B F6 C1 01 75 06 85 C0 7E 02 FF C8`,
  offsets 0x1B/0x21; no branch lands inside) and decrement only when upstream's 30 Hz beat byte
  (`propagatecounters`) is 1, exactly like the RTS counters. Verified at 90 fps: user "ровно 2
  минуты"; `summon_fixed_20260922.bin` shows −30/s. Independent of channel and Eidolon type.

### Message windows vanish fps/30 x too fast (Cid's Crucible condition) — FIXED (2026-09-26, `[Effects] MessageTimerFix`)

- **Report:** in the final mission (Invasion of the Rursus) the condition of each Cid's Crucible disappears
  almost at once at 120 fps.
- **Found with the new tools:** two `[Diagnostics] DataRing` captures (`dump/crucible_notice/`) showed
  `u32 0x14075D25C` idle, then 279 → 13 in −24 steps per 100 ms (2 per render) exactly while the window was
  up, then −1; neighbours hold the message/text ids (`+0x14` 509/511, `+0x20/+0x24` 9013/9014 or
  12017/12018). A hardware write watch on it (`WriteWatchRva = 75D25C`, `WriteWatchMinutes = 60`) named the
  writers: set to 300 at `0x1403E7527` (`mov [rsi+0x4C],0x12C`, when `[rsi+0x5C]` is 4 or not in {0,1,5};
  otherwise `r13d` at `0x1403E7521` — 270 seen for other messages), decrement only at `0x1403E90D2`, closed
  (−1) by `0x1403E93A9`.
- **Object:** `0x14075D210` (pointer in `[0x14077EC38]`, initialiser `0x1403E0440`), a message window whose
  remaining display time is `[window+0x4C]`. The shared window update `0x1403E90A0` (16 call sites) does
  `if (t > 0) t--` on every call; the crucible window gets two calls per rendered frame, so 300 = 5 s at
  30 fps but 1.25 s at 120.
- **Fix:** hook `0x1403E90C9..D4` (signature `C6 43 7C 00 8B 43 4C 85 C0 7E 05 FF C8 89 43 4C 83 7B 3C 00`,
  offsets 4/0x10; branches land only on the first byte or the resume point) and decrement only when the
  30 Hz beat byte (`propagatecounters`) is 1 — every window keeps its native per-frame count whatever its
  call count. Before the first frame-setup tick (rendered-frame counter still 0, boot only) the native
  decrement stays. Verified at 120 fps (user + write watch): the crucible condition stayed 5.06 s; three
  other messages of the same window ran at 60/s until the game closed them.
- Unverified side effect to check: the short mission-start title card may use the same window update.

### Cutscene camera clips play per rendered frame (chapter 8 Rem l'Cie scene) — FIXED (2026-09-26, `[Effects] CameraAnimRateFix`)

- **Report:** the three-part cutscene after "remain mortal" (crystal, cadets react, Rem in an office):
  at 120 fps Rem never lifts her head, her eyes glow at once, the scene ends. Replayable from the menu.
- **Method:** full script-stream traces with command arguments at 120 and 30 fps from the menu (parts 1-2
  skipped with Start in both), aligned on op 0x38B arg 8711 (Rem's model): identical until the script waits
  for the camera. Op 0x28 queues a clip on the camera (`ActorCameraEye`), op 0x62 on Rem (ch6), op 0xFB(-1,N)
  polls "camera queue entry N still pending" (`0x1401B45C0`). Camera steps: 4.67 s / 3.86 s at 30 fps,
  1.16 s / 0.97 s at 120 (exactly 4x) — the script queues Rem's next motion before her look-up plays.
  NOTE: the stream's pc column is NOT an offset into the dumped module and a skipped part ends with a fade
  (op 0xF) that looks like a branch divergence — compare the same part, aligned on a model/motion id.
- **Cause:** upstream rescales the animation rate only for `ActorCharacter`: its per-frame update
  `0x140191510` (vtable `0x1405665B8` slot 2) resets `[actor+0x5D8]` (30/fps, nudged for lip sync).
  The motion queue `0x1401B49A0` starts clips at `[+0x5D8] * [+0x5D4]`. `ActorCameraEye` (vtable
  `0x140566308`, created by op 0x27 `0x14035DB80`, type byte 3) and `ActorCamera` (`0x140566058`) update
  through `0x140190740` / `0x140190370` = `sub rsp,28h; mov edx,1; call 0x1401B49A0` and keep the base
  init's 1.0 (`0x1401B48FD`), so their clips run per render.
- **Fix:** hook both updates (signature `48 83 EC 28 BA 01 00 00 00 E8 ? ? ? ? 32 C0 48 83 C4 28 C3`, three
  matches; the two camera ones are picked by RVA and checked against their vtable slot 2 at runtime) and set
  `[this+0x5D8] = 30/fps` (exact) before the queue runs. Verified at 120 fps (user + trace
  `dump/rem_scene/fix120`): the whole scene matches the 30 fps timeline within one tick (4.64 s vs 4.67 s).
  User felt it "a touch slower" than 30 fps; the script timeline shows no difference. **Explained and fixed
  the same day: the characters, not the camera, were slow — see the next section.**
- Upstream's own camera patches (panning area introductions, `0x658FA8/0x658FAC` counters) are a different
  mechanism; no double scaling. Other scenes with animated cameras were also 4x fast before this fix.
- Script ops decoded on the way: 0x9 wait N ticks, 0xF fade to black (arg frames), 0x9F fade in, 0x20D/0x20F
  queue a motion on an actor, 0x28 queue a camera clip, 0x62 queue a motion on actor ch, 0x27 create the
  camera actor, 0x35A/0x24E event-camera frame / done, 0x401 actor motion finished (flag 0x10), 0xD8 start a
  script function thread, 0x38B/0xEE create a scene actor from a model id.

### Character animations 1.56% slow; lips flicker at the exact rate — FIXED (2026-09-26, `[Effects] CharAnimRateFix` + `AnimQuatAlignFix`)

- **Report:** after CameraAnimRateFix, in the Rem scene the camera reaches the close-up before Rem sits up and
  looks into it; she rises afterwards.
- **Cause 1 (body lag):** the layer step `0x1403BDB60` is `frame += cvttss2si(rate * 256)` (truncation). The
  inherited lip-sync nudge set the ActorCharacter rate to 29.9/fps whenever 30/fps is exact: 0.24917 at 120
  → 63/256 per render = 252 per 30 Hz tick instead of 256 (−1.56 %; clips at speed 2: 127 vs 128, −0.78 %;
  60 fps: −0.78 % / −0.39 %). The camera now steps exactly 64. The script timeline is identical to 30 fps
  (Rem's op 0x62 goes out in the same tick as each camera clip; camera polls 116/115, 117/117, 76/75,
  162/162 ticks), so the lag is pure playback. Op 0x62 appends to the motion queue (pops on finish or
  loop-count change), so the lag carries across shots. Rate details: the queue `0x1401B49A0` recomputes
  `[+0x5D8] * [+0x5D4]` (×2 if `[+0x280]&2`) on every actor update and writes it to layers 0..`[actor+0x5E7]`
  through vtable+0x240 (`0x1401B38D0`); a clip start resets layer 0's rate to 1.0 after that, and the global
  animation pass runs before the actor loop, so every clip's first step is +256. Float-time consumers
  (blend `0x14003A870` dt = rate/30, overlay fades `0x1401B40D0`, the event player's |rate| > 1 test) use the
  untruncated rate. The float test `30/fps * fps == 30.0f` is also true at 90 and 144 (and most other caps),
  so those were nudged too — the old comment "keep the true ratio for 90" was wrong in practice.
- **Cause 2 (why the nudge "fixed lips"):** user A/B at 120 fps, same scene, one key: step 63 (29.9/fps) =
  lips right, Rem late; step 64 (30.1/fps, integer-identical to exact 0.25) = lips flicker, Rem on time.
  Static search found no code that reads the rate for mouths: the face updater `0x1403AEC90` (2D mouth
  pattern `[+0x1220]→[+0x554]`, jaw `[+0x1227/0x1228]` → quaternion `[+0xE1C]`, applied as `rest[+0xE2C] ×
  delta` in `0x1403ADAA0` every render) is gated to 30 Hz beats and never reads layers; the mouth texture is
  pasted by `0x1403A0050` only when the pattern index changes. The real mechanism is the save-stone one
  inside a clip: the pose sampler lerps 16-bit quaternion components between consecutive keys, and the face
  overlay clip has sign-opposite neighbours. `[QuatAlign]` log (the test PC, 120 fps): layer 3 of a 91-bone
  model, bones 25/26 (mirror pair, ±y) and 28 — the lip corners and the mouth centre — e.g. prev
  `(0,0,0,+32766)` → cur `(100,−100,0,−32762)` at frames 0, 39, 42, 52, 58, 59 of a 60-frame loop. At
  frac 128 the lerp gives `(50,−50,0,2)`: a 180° flip of the lip bone for one render. Step 64 samples every
  key interval exactly at frac 128 (fractions 0/64/128/192, every 4th render = 30 Hz flicker); step 63 lands
  on 128 once per 256 renders, which the eye does not see. At 30 fps frac is always 0 and the lerp never runs.
- **Fix:** `AnimQuatAlignFix` (default 1, >30 fps): after EVERY cursor move of the sampler (advance or
  rewind) and for every layer, align prev to cur (`AlignLayerQuats`, negate prev's four components when
  dot < 0, saturating −32768 → 32767, which the game's 16-bit `neg` in `0x1403BEA50` cannot). Hooks:
  `0x1403BEBCC` (advance path, 7 bytes, also sets `r14b = 1` like the rewind path) and `0x1403BEBEA..FB`
  (the flag-4 test + `call 0x1403BEA50` → `AlignLayerQuats(layer)`). Only prev `+0x44` is touched; the
  decoder accumulator `+0x42` never. Supersedes AnimLoopSeamFix (its one-byte patch is skipped when this
  is on). `CharAnimRateFix` (default 1, requires AnimQuatAlignFix): nudge UP, 30.1/fps, which truncates to
  the exact step at 40/48/60/80/96/120/240 for factors 1, 1.5, 2. Verified by the user at 120: Rem in time,
  lips steady, save stone steady.
- Side notes from the investigation (not fixed): per-render counters `actor+0x5DC/+0x5DE` (frames since
  the motion started, script op 0x241 / property 98) and the actor colour fade `0x1401B2D80` (op 0x9C, used
  on Rem in this scene) count per render, fps/30 x fast. At odd caps (45, 72, 110, …) 30.1/fps gives one
  step per render more than the exact camera rate.

### Area attacks damaged only the first target above 30 fps — FIXED (2026-09-28, `[Effects] HitDedupPerVictim`)

- **Found by the audit (B2), confirmed in play.** Upstream's damage dedup hooks the entry of the damage call
  `0x14025FD20(ecx attacker channel, rdx victim actor — [rdx+0x18] its channel, r8/r9 hit info inside the
  attack object, ...)` and returns eax = 1 ("hit") without damage when the CALLER's rbx — the attack object —
  is already in the 20-slot `damage_and_audio_triggers` list. The list is shared with the audio dedup and is
  cleared by the 30 Hz beat hook only after a beat window with no insert (`reset_list` toggles), so an entry
  lives one or two windows. Loops that walk several victims with one object (e.g. `0x140296240`, callers
  at `0x1402962F3`/`0x1402964E2` pass the victim in rdx) lost every victim after the first, and callers such
  as `0x140291018`/`0x1402ADD42` treat the fake eax = 1 as a hit and set the victim's already-hit bit.
- **Evidence (`[Diagnostics] TraceHitDedup=1`, read-only counter before the dedup check):** 120 fps, 5 min:
  6 lost new victims (Sice's scythe on four enemies at once: one hit, victims ch 7/8/13 lost at one beat;
  Ace's spells lost 3) against 5 real same-victim repeats.
- **Fix:** key the list on the (object, victim) pair, `rbx + rdx * 0x5851F42D4C957F2D` in r11 (free at the
  entry; computed after the trace call). Verified at 120 and 60 fps: 0 lost, 9 extra victims of one attack
  landed ("extra victims" counter), 12 same-victim repeats still suppressed, peak list use 7/20.

### Perceived "everything twice as fast" with the Toolbox (Nexus feedback, 2026-09-22)

- With `[Movement] AnalogTiers=1` a fully tilted stick runs at the top tier (1.5x, or 2x after
  L3) instead of the stock tier 1, and dodges ALWAYS use the cap tier's m2 (`DashAtCap`, 0.5.3:
  `actor+0x2a8 = base * m2` from the 1.5x/2x row, never the analog m1, so a weak tilt cannot
  produce a slow-motion dodge; §6). Against upstream Banz99 0.2 (its latest release, 2022-12-26,
  ASI MD5 `67DFDCD474ECB7F796B27887FE42E85F`, same d3d11/keystone) at 60 fps this reads as
  "everything, dodges included, is faster". Intended; `AnalogTiers = 0` restores stock pacing.
- Second A/B on the second PC, 90 fps, 720p, Akademeia teleport (2026-09-22, user observation): upstream 0.2
  shows the party member walking in place before the portal (our `WalkLegMinTicksFix`), the portal
  effect flickering, and the controlled character wobbling side to side on turns; our 0.5.10 build
  shows none of the three. The turning wobble was fixed together with Commander Schmitz by
  `TurnPhaseFullRate` (0.5.1, user recollection): upstream's CutsceneWalkFix quartered the facing-servo
  step, the servo is rebuilt from phase 0 every frame, so with h = 30/fps it decays geometrically and
  overshoots; full-rate servo steps restore the native turn (§4 "Facing servo").
- A genuine double-speed failure also exists: the frame limiter is written first in the
  `[OverrideFramerate]` block, so a `[MISS]` later in the pass (`[Patch] ABORTED`) leaves the
  cap at 60/120 without any timing compensation and without the camera patches. Fallback
  (rewrite 1/30 in the catch handler) not yet implemented; check the reporter's log first.

### Enemies "speed up" at 60 fps (Nexus report, 2026-10-31): scripted enemy turns 2x — FIXED (`EnemyTurnFullRate` default 0); per-render actor timers — FIXED (`[Effects] ActorTimerFix`, verified 2026-10-31); vertical motion (`[Movement] VerticalMotionFix`, default 0, NOT verified: first build changes Qator's hop height)

- **Report:** fvbc on Nexus, "game occasionally speeds up, mostly apparent with enemies", FpsCap=60, default
  movement, The Capture of Togoreth Stronghold (video). Reproduced on the test PC from the chapter-2 stairwell save
  (Commander Schmitz ch6 class `0x2022` HP 6718, soldiers `0x2016` HP 322, officers `0x2019` HP 604, then
  Qator `0x200B` HP 6015) at 30 / 60 / 120 with new read-only diagnostics: `[Diagnostics] TraceEnemySpeed`
  (50 ms sampler of every mover: horizontal bursts above `TraceEnemySpeedMin` u/s, body-yaw turn bursts from
  `mover+0x6C` above `TraceEnemyTurnMin` deg/s, vertical bursts above `TraceEnemyVertMin` u/s, warps,
  actor/mover disappearance; the first build read the move direction `mover+0x58/+0x60`, which equals the facing
  only while standing), `TraceMotionSpeed` (CMD134 factor starts per side) and `TraceActorTimers` (1 ms
  high-resolution sampler of the per-render actor bytes). Tools `docs/tools/enemyspeed_stats.py`,
  `docs/tools/actortimer_stats.py`; captures `dump/togoreth_20261031/*` (run60/run30, turn60/turn30,
  turnoff60(b), qator120off, vert60/vert30). Sampler caveat: `GetTickCount64` steps 15.6 ms, the loop period is
  ~51 ms, so a constant speed v shows up at discrete levels (0.71 / 1.07 / 1.42 × v); samples above 2000 u/s
  end a burst (dash peaks are capped).
- **Horizontal speed is NOT faster at 60.** Matched legs (same channel, clip, start) 60/30 = 0.94–1.08; soldier
  cruise ~540 u/s true, long run 1077 at both rates; boss cruise ~720. CMD134 was never called for an enemy
  (0 starts in 160 s), so the tier/analog multiplier is excluded; the boss's `x1.25` on `[+0x5D4]` comes with
  clip 49 at both rates.
- **In-place enemy turns WERE 2x faster at 60 (4x at 120) — `EnemyTurnFullRate`.** Standing turns (clips other
  than run): soldiers 427 deg/s at 30 vs 1123 at 60, boss 521 vs 1406; with `EnemyTurnFullRate=0` at 60: 475
  and 684 (second run 300–605). Running turns (steering) equal: 403 / 495 / 506. Mechanism (static analysis,
  agents 2026-10-31): the `+0x1a8` profile clock is called exactly once per rendered frame per actor
  (`0x1401B960F` in the evaluator `0x1401B9580`, from the ActorCharacter update `0x140191510`). Rule 2 stepped
  every enemy turn 1.0 per render whatever its phase, so a persistent turn of D ticks took (D+1)/fps s. Persistent
  (phase > 0) turns: the state-4 turns built by `0x14019AFD0` (opcode-table entries `0xD8`, `0x100`, `0x14F`,
  `0x156`, and the AI re-aim step `0x140274880` via entry `0x17F`: when keyframe event bit 19 of `[aib+0x1A0]` is
  set and the per-target metric `[actor+0xB30+ch*4]` exceeds 30, the enemy re-aims with D = `[aib+0xE1]` ticks —
  attack windups tracked the target 2x faster, which is the "occasional" part), `0x14019B2E0` / `0x14019B370`
  (entries `0x14`, `0x1D`, `0xD6`) and the facing built at the start of a run leg (`0x14019B8A8`). Servo turns
  (phase 0: state 3 `0x14019BACC`, state 1 `0x14019BDD4`, the per-frame facing request) are rebuilt from phase 0
  every frame and are unchanged (`TurnPhaseFullRate`, the Schmitz fix). Qator — the reason the key existed — and
  Schmitz replayed at 120 with the key off: no stall (longest state-4 stretch 1.8 s and the turn reached its full
  phase; the 2026-09-04 freeze was endless), Qator killed; `AiEventKeepFix` was the real Qator fix all along.
  User at 120: enemies less twitchy, Break Sight / Kill Sight easier to catch. **Default 0 since 2026-10-31**
  (opt-in value 1 kept). Untested residuals: with `TurnPhaseFullRate` servo turns of every actor advance one
  30 Hz tick per render (fps/30 x in wall-clock, 8-render state-3 budget); a persistent turn rebuilt on every
  30 Hz tick still advances 1.5x at 60 because each rebuild steps 1.0 on its first frame.
- **Per-render actor timers — `[Effects] ActorTimerFix` (default 1, verified 2026-10-31 at 60 fps: hit-freeze 2 units 49-68 ms vs native 66, protection 9 units 299-300 ms, 30 units 1001 ms; user: fights easier to win).** The actor resource update
  `0x1401A0EE0` (called once per rendered frame at `0x1401915C7`, no class filter, battle gates
  `[0x1406578F4]`/`[0x1406578FE]`) steps 30 Hz-authored counters unscaled: byte `+0x5E6` hit-freeze (2 per hit
  that beats poise by exactly 1 or whose reaction is blocked, `0x1401964EF` via TakeDamage `0x140198F1F`; 10 from
  the attack handlers `0x14029AAB9` / `0x14029B61B`; while > 0 `[+0x280]` bit 0 is set: motion queue rate 0 and
  no step (`0x1401B4A27`), profile clocks stop (`0x1401B95CB`), movement controller skips (`0x1401AA4BF`) =
  hit-stop), byte `+0x9B8` timed protection (10 at `0x14025CB82`, 30 at `0x14025F112`; `0xFF` is held by the
  player-action handlers `0x1402D44D0/0x1402D56B0/0x1402DACA0` and cleared by `0x1402DC520`, not stepped; it
  gates `0x140197510` only when the caller passes flag 1 and suppresses status DoT ticks; the main damage call
  `0x14025FD20` never reads it), byte `+0x9A9` Kill/Break Sight lockout (10 on entering the downed state
  `0x140198695` / `0x1401A7D19`; `0x1401BDF80` applies the sight effect only when it is <= 5), word `+0x9A2`
  stun build-up gauge (`0x140196840` adds attack[0x1d]*8 per hit when prop 33 is set; at >= `[9a0]` the victim
  gets stun status `[a09]` = `[9a6]` and takes 2x damage at `0x1401BD775`; decays by `[+0x9A5]` per render),
  word `+0x9DC` downed-state timer (set to `[9de]` = 60 on a lethal hit with prop 92: state 3, HP = 1; on expiry
  heal `[9d8]/128` maxHP and stand up: 2 s native, 1 s at 60, 0.5 s at 120), word `+0x9BA` script lifetime
  (prop 58/59, `[6bc]=2` at <= 0). **Measured** with `TraceActorTimers` on the same fight: `5E6` 2-unit
  episodes 66.8 ms at 30 vs 33.1 at 60; `9B8` 9 -> 300 vs 150 ms, 30 -> 1000 vs 500 ms: 33.3 vs 16.6 ms per unit,
  party and enemies alike. So hit-stop, stun decay, the downed state and timed protection ran fps/30 x fast (4x at
  120). Also ungated in the same function and NOT patched yet: status DoT tick counters `+0xA98/+0xA9A` (+3 per
  render), status HP drain/regen (`0x1401A11EE/0x1401A11B4`), dead-actor fade `+0x9EC`. The fix gates the steps on
  the 30 Hz beat byte (`propagatecounters == 1`, as `SummonTimerFix` in the same function) in four regions that are
  unique in the dump and entered only at their first byte: `0x1401A1CD6..0x1401A1D20` (5E6/9B8/9A9; the stop flag
  `[rbp-0x38]` is still raised on every render while the counter is non-zero), `0x1401A1167..0x1401A118E` (9A2;
  ebx = 0 on both native paths), `0x1401A14A3..0x1401A14B2` (9DC; the cmp feeds the native jg) and
  `0x1401A1EF9..0x1401A1F02` (9BA). The Kill/Break Sight window itself is keyframe/script based and was measured
  real-time-correct earlier (§9), so it must not change.
- **Flyer vertical motion is fps/30 x fast (fix in preparation).** Only flyers (`+0xD9`, set by SetActorParam 65
  at `0x1401A4AF6`, copied at `0x14019DCCB/0x14019F6E6`) take a Y delta from the speed mover: the evaluator
  passes dir.y = 0 for ground actors (`0x1401B987F`) and the physics update zeroes v.y for them
  (`0x1401BA606`). Ground enemies and the party get their Y from the navmesh snap, root motion (`mover+0xA30`,
  compensated by the clip rate; soldier jumps = animation, vertical bursts equal at 30/60) or SetPosition. For
  flyers every vertical source runs once per render, unscaled: ballistic fall (`+0x6B9` bit 0x20,
  `0x14019C480` -> push `0x1401BA8E0` with g = `[0x14065598C]` = 9.8), hover servo (bit 4, push
  min(0.2|e|, 0.8*`[+0x2A8]`) toward floor + `[+0xCE4]`), flyer walk legs (`0x14019BCC0`, velocity cap
  `[+0x110]+[+0x10C]`), air drag |v| -= `[+0x10C]` per render in `0x1401BA3A0`, and the speed-mover Y store
  `0x1403C0C42` (upstream's inject at `0x1403C0C3C` scales only X/Z). The path in units is the same at any fps,
  only the time shrinks: Vajra roof hover drop of 100 u takes 375 ms at 30 vs 125–150 ms at 120; Qator rose
  10 -> 98 in 32 ms at 120 (speed falling in steps of exactly 40 = the drag). `BossVerticalFix` (scales only the
  position step) is incomplete: it half-fixes gravity/hover (sqrt factor) and shrinks drag-coast hop apexes by
  30/fps (Qator's ~112-u hop would become ~56 at 60). A complete fix must also scale the per-render velocity
  changes (push magnitude, drag, g) and leave one-shot impulses alone; never scale the camera mover
  (`0x14074F0B0`, same speed-mover function). Flyers in this game: Qator (mode 6), Vajra roof scene, Zu/dragon
  types, whatever a script flags.
  **First implementation (`[Movement] VerticalMotionFix`, 2026-10-31 night, default 0, kept out of the 0.5.12 texts):**
  (1) the speed-mover Y step scaled by k (the old `BossVerticalFix` arm, now with the camera mover `0x14074F0B0`
  excluded by pointer), (2) ground gravity: `mover+0x80 += 4.0` per render at `0x1403AFB64` / `0x1403AFBE3` (the 4.0
  at `0x14057FFAC` replaced by 4.0*k) and `dy -= v` at `0x1403AFF1E` scaled by k, (3) flyer pushes: in the push function
  `0x1401BA8E0` (callers: walk-leg acceleration `0x14019BEA8`, gravity `0x14019C524`, hover `0x14019C608`,
  locomotion `0x1401AA803/0x1401AA9EF`; one-shot impulses use AddImpulse `0x1401BACD0`, not this) the magnitude
  xmm6 and the drag re-add / cap register xmm13 are multiplied by k at `0x1401BA9FF` when `[rbx+0xD9]` is set, and the
  subtractive drag at the physics join `0x1401BA63D` likewise, both under upstream's cutscene gate. **Test (60 fps,
  `dump/togoreth_20261031/vertfix60`, TraceBossPos ch6 = Qator):** his hops reach only 56-67 u (apex) instead of
  98-118 unfixed at 120 (= native by the per-render invariance argument); in the hop the vertical velocity `face.y`
  still decays ~2.7 per render (22.9 -> 17.4 -> 9.2 -> 3.7 -> 0.95 over ~8 renders) while the position step is
  halved, i.e. the velocity-change scaling did NOT take effect on that decay and only the Y-step scaling did (the
  `BossVerticalFix`-alone failure mode: apex x30/fps). Suspects: the `[rbx+0xD9]` flyer test at `0x1401BA9FF` (planner
  B put the hook on the flyer branch at `0x1401BA965` instead, where no test is needed), or a decay path outside the
  push/drag pair. The user noticed nothing odd in the fight, but Qator's platform reach (Y ~118) may be affected.
  Next: 30 fps BossPos control of the same hop, a per-render dump of v/y around one hop, then re-check the hooks.
  **Merged agent plan (flyer-vertical-fix-plan, 2026-10-31 23:40):** P1/P2/P3 as built are confirmed (signatures, offsets,
  liveness re-checked). Predicted for a drag-coast hop at 60 with the full fix: apex ~110 (stock 88, Y-step-only 44);
  Vajra roof drop 340-410 ms (stock 60: ~190). The observed decay of `face.y` (22.9 -> 17.4 -> 9.2 -> 3.7 -> 0.95,
  ~x0.53 per 47 ms sample) does not look like a linear drag at all but like the **mover script-hop channel**: in
  `0x1403AFC30` (`0x1403AFC52..0x1403AFC76`) `dy += [mover+0xE0C]` every render and `[+0xE0C] *= [+0xE10]` (geometric
  decay) every render, untouched by P1/P2. The plan's deferred P4 gates the decay on 30 Hz beats and scales the dy term
  by k (asm in the workflow output tasks/wfdhkr6b6.output, section 1); install it only if the D1 diagnostic shows
  `e10 != 0` for the hopping actor. D1 = extra fields on the `[EnemyVert]` line: `fly=[a+0xD9]`, `gate=` (mode 1 and cell
  set), max |`mover+0xE0C`|, `[+0xE10]`, max |`+0xE6C`| / |`+0xE7C`|. The plan also wants the switches split:
  `FlyerVerticalFix` (P1+P2+P3) separate from `VerticalMotionFix` (ground gravity), both default 0 until verified.
  `ActorTimerFix` beat gating note: a 2-unit counter now lasts 33-67 ms depending on the beat phase (native 67,
  unfixed 33 at 60); `9B8` 9/30 units: 300/1000 ms exact.
- **Other candidates, for the record.** The frame limiter `0x14007C6E0` busy-waits (QPC + Sleep(0)) and sets
  last = now, so there is no catch-up: game speed = actual fps / cap <= 1; on a PC that dips below the cap the
  return to 60 reads as a speed-up (cannot be fixed by the mod; ask for a frame-time overlay). A `[Patch]
  ABORTED` after the limiter write is a permanent 2x with a popup, not "occasional". An old 0.5.7–0.5.9 INI with
  `AnalogTiers=1` speeds up the player (and allies through m1), never enemies. Leads not followed yet: upstream's
  `FindAll("00 0F 2F 05 ? ? 2E 00 F3 0F 11 87 00 01 00 00", 2)` matches 3 sites (log `[WARN] for_each matches=3
  expected=2`, Patch.cpp ~L7833): an unplanned third site is patched; upstream's cutscene gate cell `0x6D1CEC` is
  written by script opcode `0x88` (`0x1403609BA`) and could switch off the X/Z speed scaling in game mode 1.

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
- Ability use is not a separate multiplier for the reported movement acceleration:
  weapon draw alone reproduces it. The native 20% run-speed stance difference is
  intentional; excessive high-FPS dodge cadence was a separate timing bug, fixed
  by the three switches in §6. Do not flatten native stance speeds to hide it.
- Combat A/B with the mod (same area, 30 vs 120 fps, 2026-09-05): damage per hit identical (183 vs 184),
  Kill Sight window 1.00 s both (30 vs 118 sound requests), hits taken 6 vs 3 — no evidence that 120 fps
  makes fights harder. Perceived difficulty = the game's accuracy/RNG. (`TraceCombat` + `TraceSounds`.)
- The end-of-chapter-1 voice cutoff happens at vanilla 30 fps too.
- The save stone's once-per-spin hitch at 120 fps is NOT an effect-engine (Fec) element and NOT the
  frame counter/loop wrap: hiding every Fec drawable class left it, the layer frame is continuous across
  the wrap; it was the pose sampler's quaternion lerp across a sign flip (2026-09-22).

## 10. Fixes shipped in this fork (post-0.5)

| Version | Switch (`[Movement]` unless noted) | What |
|---|---|---|
| 0.5.1 | `TurnPhaseFullRate` | Commander Schmitz stair entrance: servo at full rate |
| 0.5.2 | `AiEventKeepFix`, `EnemyTurnFullRate` | General Qator Bashtar freeze |
| 0.5.3 | `AnalogGlobalsFix`, controlled-character lookup, `DashAtCap`, `AiCountdownFix` | analog movement after character switches, dash speed, enemy decision pacing |
| 0.5.5 | `ScriptVarDedupAll` (default 1), `ScriptTick30Hz` (default 0), `[OverrideRes] AllowUnsupportedRes` | frame-aware script `++/--` dedup on all stores (chapter 3 mission 2 hang); resolution fallback; HangWatch/TraceScriptOps diagnostics |
| 0.5.6 | `ScriptVarDedupAll` (whole step + 1/64 nudge scheme) | 0.5.5 dialogue 4x repeat, idle enemies; script counters exact at tick boundaries |
| 0.5.4 | `[Camera] LockFollowPercent`, `LockDeadZoneDegrees`; `[Movement] StickSaturationPercent` | lock-on camera soft follow + dead zone; diagonal stick saturation; tuner window regrouped, tooltips fixed | **(the two Lock* keys REMOVED 2026-09-22: inert in normal lock-on, see "Lock-on camera")**
| Unreleased | `MotionStartWaitFix`, `ScriptWaitFrameFix`, `DodgeCadenceFix` (experimental, default 0; enabled on the test PC) | verified native 30-FPS dodge cadence/range at 120 FPS, tier 3; preserves native stance difference and lip-sync correction outside dodges |
| Unreleased | `MpRegenFix` (experimental, default 0; enabled on the test PC) | removes fourfold MP restoration at 120 FPS; native MP/AG rates verified, final +1 grant (~6 MP) player-favourable difference permitted by user (§6) |
| Unreleased | `[Effects] AnimLoopSeamFix` (experimental, default 0; enabled on the test PC) | save-stone spin seam at >30 fps: quaternion hemisphere alignment after every loop rewind |
| Unreleased | `[Effects] SummonTimerFix` (experimental, default 0; enabled on the test PCs) | Eidolon summon timer once per 30 Hz frame instead of per render (upstream #20) |
| Unreleased | `[Effects] MessageTimerFix` (default 1, verified 2026-09-26) | message windows (Cid's Crucible condition) count their display time on 30 Hz beats |
| Unreleased | `[Effects] CameraAnimRateFix` (default 1, verified 2026-09-26) | cutscene camera clips (ActorCameraEye/ActorCamera) at 30/fps: chapter 8 Rem scene |
| Unreleased | `[Effects] CharAnimRateFix` + `AnimQuatAlignFix` (default 1, verified 2026-09-26) | character animations at the exact step (30.1/fps instead of 29.9); quaternion sign alignment on every key of every layer (lip flicker; supersedes AnimLoopSeamFix) |
| Unreleased | `[Effects] HitDedupPerVictim` (default 1, verified 2026-09-28 at 120 and 60) | area attacks damage every target: the upstream damage dedup keyed on attack object + victim (audit B2) |
| Unreleased | `[Gameplay] ExpMultiplier` (default 1 = off; 10 on the test PC since 2026-09-25) | EXP gains × N for catching up on levels; scripted level changes stay exact (§11) |
| Unreleased | `EnemyTurnFullRate` default 1 -> 0 (2026-10-31) | enemy scripted turns no longer 2x/4x fast above 30 fps (Togoreth report); Qator + Schmitz replayed clean at 120 with 0 |
| Unreleased | `[Effects] ActorTimerFix` (default 1, verified 2026-10-31 at 60) | hit-freeze, timed protection, sight lockout, stun gauge decay, downed timer and script lifetime step on 30 Hz beats (measured 2x fast at 60) |
| Unreleased | `[Diagnostics] TraceEnemySpeed` (+`TraceEnemySpeedMin/TurnMin/VertMin`), `TraceMotionSpeed`, `TraceActorTimers` | read-only per-mover speed/turn/vertical bursts, CMD134 factor counts, 1 ms actor-timer sampler |
| — | `AnimLastFrameFix` (default 0) | superseded; its asm form is rejected at runtime |
| — | `BossFixPace/Nav/Turn/Profile`, `ProfileVelocityFix`, `BossVerticalFix` (default 0) | dead or superseded experiments (`BossVerticalFix`: incomplete flyer Y fix, see the 2026-10-31 section) |

## Patch framework hazard: never pass 0.0f as a `%N` float (2026-09-20)

`FindOrInsertFloat(0.0f)` does not allocate a slot: it returns the first FREE entry of the float
table, and the next float inserted by any later `ParametricASMJump` overwrites it. The upstream
sub-1080p "Font fix" passed inset 0 below 1920x1080, so its glyph inset silently became the next
inserted value: 30/fps before 2026-09-16 (0.33, invisible), then MotionStartWaitFix's 2*fps/30
(6 at 90 FPS), which cropped every glyph at 1280x720 (rows/columns of pixels missing, worst in
Cyrillic text; digits and baked Latin labels mostly survive). 1920x1080 does not install the hook,
larger resolutions use a real non-zero inset. Fixed in 0.5.9 (commit a430e44): the hook is skipped
when the inset is zero. User-confirmed at 1280x720/90 on the second PC. Rule: if a hook needs zero, use
`xorps`, or do not install the hook.

## 11. Character roster, EXP and levels (static analysis 2026-09-25; `[Gameplay] ExpMultiplier`)

Read from the unpacked image and Ghidra decompiles. Multiplier runtime-verified on the test PC 2026-09-25
(chapter 7, x10, build `D1427FAC9CCE4AD3E957FDF6E93C6156`): 24 scaled gains of 155 or 465 base EXP each,
+5,890 -> +58,900 EXP, level-setter calls 0, no hook errors; levels visibly rose in game.

- **Roster records**: the local player's characters live at `0x1406CB260 + idx*0x220`, 0x2B records
  (the 14 cadets are idx 0..13; the character id word is at `+0x4`). Co-op copies of the other
  players' rosters: `0x140718AA4 + i*0x641C`. Every roster helper resolves `slot` the same way:
  slot == controlled slot (`[0x740598]` when `[0x74126D]||[0x740940]`, else 0) or −1 → local roster.
- **Record fields**: `+0x28` level (u16); `+0xF4` EXP (u32, clamped to 99,999,999); `+0xE8` flag word
  (bit 6 = actor property 0x90); `+0xEA` flags (bit 1 = receives roster-wide EXP rewards, bit 4 = left
  out of the checksum); `+0xEE` Eidolon timer mirror (§8); `+0xFC` a 0..999 value (free-time reward
  type 0x0D).
- **EXP table**: pointer `[0x140657C30]`, 8-byte rows; `row[L-1]+0` = total EXP of level L, the byte at
  `+4` is summed per gained level and handed back through AddExp's out-parameter.
- **AddExp `0x140256730(slot, idx, delta, int* out)`** — the single writer of `+0xF4`. It first verifies
  a roster checksum through `0x14024D800(7, value)` (value = `~sum << 3 ^ 0x46CA6F51` over `+0x3C`,
  `+0x40..+0x67` and `+0xF4` of every record without `+0xEA` bit 4) and returns 0 WITHOUT adding when
  it fails — this is why poking EXP directly in memory "does nothing" / trips the game's tamper check.
  Then `EXP = clamp(EXP + delta, 0, 99,999,999)`, level = `0x140253E70(slot, idx)`, one growth call
  `0x140254360` per gained level, fresh checksum stored at `0x1406C5028`; returns the levels gained.
  GetExp = `0x1402532C0(slot, idx)`.
- **Record level setter `0x140256090(slot, idx, level)`**: target = `row[level-1]` (below 99: a random
  value in `[row[level-1], row[level]-1]` via the RNG range helper `0x1401D52F0`), then
  `AddExp(slot, idx, target − EXP)` and `0x140256A80(slot, idx, 1)`. Callers: actor level changes of
  party actors (`0x1401A7120` = actor SetLevel, word `[actor+0x968]`; the mover's `+0x2BA/+0x2BB` hold
  slot/idx), actor re-init `0x1401A3E40`, the actor property setter `0x1401A4540` (case 0xE = level),
  network sync and script commands. Any EXP scaling must leave this path alone.
- **EXP sources (all end in AddExp)**:
  - Kills: `0x14019FE90(actor, base, level, flag)` — base × arg3, level-difference bonus/penalty from the
    byte table `[0x140657E30]` (`+0xEC` bonus per level below the enemy /32, `+0xED` penalty diff²/64,
    `+0xEE` when `[actor+0x874]` bit 3, `+0xEF/+0xF0` co-op player-count factors), × byte
    `[actor+0xAD8]`, clamp 0..99,999 → `0x14019CEB0(actor, exp)` (adds EXP-bonus effects of type 6 from
    the list at `0x14065B170`, count `[0x14065B15C]`; on level-up: popup + sound `0x895450`).
  - Free-time rewards `0x140241180` (type 0x0E: a percentage of the current level band) → `0x14019CEB0`.
  - Reward dispatcher `0x14038E100` type 8 → `0x140253220(?, n*1000)`: every cadet with `+0xEA` bit 1.
  - Script handler `0x140369ED0` (table cell `0x14061B0F8`): all 14 cadets, amount = (int)float `[arg+0x38]`.
- **`[Gameplay] ExpMultiplier=N`** (default 1 = off, capped at 1000): hook on the add in AddExp
  (`0x1402568A5`: `mov ecx,[r15+0xF4]; movzx ebp,[r15+0x28]; add ecx,r14d`, r14d = delta, rax/rdx dead,
  the only branch into the region lands on its first byte). Positive deltas are multiplied unless the
  return address `[rsp+0x4B98]` is the level setter's call site (`0x1402560E7`, checked by signature and
  by its call target at runtime); the scaled delta is capped at 99,999,999 so EXP + delta cannot wrap
  before the game's own clamp. The checksum stays valid because AddExp rebuilds it after the add.
  Totals are logged as `[Gameplay] EXP xN: <gains>, +<original> -> +<scaled>`.
