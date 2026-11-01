# FF Type-0 HD Toolbox 0.5.11

Area attacks damage every target, character animations and cutscene cameras keep
the original pace, message windows last as at 30 FPS, and an optional EXP
multiplier. Changes since 0.5.10:

- New setting `[Gameplay] ExpMultiplier` (default 1 = off): multiplies all EXP the
  party earns, from kills and rewards. Levels that the story sets by itself stay
  exact. Verified in-game at x10 in chapter 7: every gain arrived exactly ten times
  larger.
- Cid's Crucible conditions (and other message windows) stay on screen as long as
  at 30 FPS. Above 30 FPS they vanished fps/30 times faster (1.25 s instead of 5 s
  at 120 FPS). Built in, like the other high-FPS fixes (`[Effects] MessageTimerFix`
  = 0 turns it off). Verified in-game at 120 FPS: 5.06 s.
- Cutscene camera animations play at the original speed above 30 FPS (they ran fps/30
  times faster). In the chapter 8 ending Rem now lifts her head and looks into the
  camera before her eyes glow; the scene matches 30 FPS within one frame. Built in
  (`[Effects] CameraAnimRateFix` = 0 turns it off).
- Character animations keep the exact original pace at 60 and 120 FPS (90 FPS is
  unchanged, 0.4% slow). They ran 1.6% slow at 120 FPS (0.8% at 60), enough for
  Rem to lag behind the camera in the chapter 8 scene. The old lip-sync workaround caused it; the lip flicker it hid is now fixed
  at its source (a sign flip between animation keys, the same cause as the save
  stone jerk), so lips and save stones stay steady. Built in (`[Effects]
  CharAnimRateFix` / `AnimQuatAlignFix` = 0 turn them off). Verified in-game at 120 FPS.
- Attacks that hit several enemies at once damage all of them above 30 FPS. Before,
  only the first target took damage and the others were skipped (for example Sice's
  scythe on a group, or area spells). Built in (`[Effects] HitDedupPerVictim` = 0
  turns it off). Verified in-game at 120 and 60 FPS.
- Vertical mouse look is back to the stock response when the camera curve settings
  are on (it was multiplied twice, so small mouse movements barely moved the camera).
- Smaller fixes for other caps: script waits no longer run one frame too long at
  90 FPS; a cap above 120 now runs every fix at 120 (the game itself is capped
  there); caps that are not a multiple of 30 (for example 100) use the right frame
  counts in `WalkLegMinTicksFix` and `FirstFrameFix`.
- With `[Camera] TuneWindow = 1` the lock-on turn limit now also works when
  `LockTurnMaxDegPerSec = 0`.

## Defaults and updating

Same defaults as 0.5.10, with the EXP multiplier off. From any 0.5.x: replacing the
ASI is enough; to use the multiplier with an old INI, add the `[Gameplay]` section
from the supplied INI. INIs from 0.5.7-0.5.9 have `AnalogTiers = 1` (analog
movement); set it to 0 for the original movement. INIs from 0.5.7 lack
`[Cutscenes] PartySceneFix`; add `PartySceneFix = 1` for the cutscene fix.

Linked kill-switches: `AnimQuatAlignFix = 0` also turns off `CharAnimRateFix`;
`AiEventKeepFix = 0` also turns off `ScriptMotionEventFix`; `TurnPhaseFullRate = 0`
also turns off `EnemyTurnFullRate`.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
