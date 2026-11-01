# FF Type-0 HD Toolbox 0.5.12

Enemies no longer turn, recover from hits or get up faster than at 30 FPS. Changes
since 0.5.11:

- Enemies turned to face you two times faster at 60 FPS and four times faster at
  120 FPS (their scripted turns, for example re-aiming during an attack wind-up).
  A Nexus report described it as "the game occasionally speeds up, mostly enemies".
  The 30 FPS pace is restored: `[Movement] EnemyTurnFullRate` is now off by default.
  It was a 0.5.2 workaround for General Qator Bashtar's freeze, which 0.5.2's
  `AiEventKeepFix` fixes on its own. Verified in-game at 120 FPS: Qator and the
  Togoreth stairwell commander fight normally; at 60 FPS turn rates are back near 30 FPS.
- Hit-stop, stun build-up and knock-down last as long as at 30 FPS. The game counted
  these timers per rendered frame, so at 60 FPS an enemy (and your own character)
  froze after a hit for half the time, the stun gauge drained twice as fast and a
  knocked-down enemy got up after 1 s instead of 2 (a quarter of all that at 120
  FPS). Built in (`[Effects] ActorTimerFix` = 0 turns it off). Verified in-game at
  60 FPS: hit-freeze 50-67 ms (33 before, 66 at 30 FPS) and 300 / 1000 ms protection timers,
  as at 30 FPS.
- New support diagnostics, off by default: `[Diagnostics] TraceEnemySpeed`,
  `TraceMotionSpeed`, `TraceActorTimers`.

## Defaults and updating

Same defaults as 0.5.11. From any 0.5.x: replacing the
ASI is enough. If your INI has `EnemyTurnFullRate = 1` (only if you added it yourself),
remove it or set it to 0 to get the turn fix. To use the EXP multiplier with an old INI, add the `[Gameplay]` section
from the supplied INI. INIs from 0.5.7-0.5.9 have `AnalogTiers = 1` (analog
movement); set it to 0 for the original movement. INIs from 0.5.7 lack
`[Cutscenes] PartySceneFix`; add `PartySceneFix = 1` for the cutscene fix.

Linked kill-switches: `AnimQuatAlignFix = 0` also turns off `CharAnimRateFix`;
`AiEventKeepFix = 0` also turns off `ScriptMotionEventFix`.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
