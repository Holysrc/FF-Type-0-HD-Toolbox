# FF Type-0 HD Toolbox 0.5.10

Two high-FPS fixes, fixes always on, analog movement off by default. Changes since 0.5.9:

- Eidolon summon timer: above 30 FPS the two-minute summon ran out fps/30 times
  faster (at 90 FPS in 45 seconds). It now counts real seconds. New setting
  `[Effects] SummonTimerFix = 1`.
- Looping animations no longer hitch once per loop above 30 FPS. Most visible on
  the spinning save point, which jerked at the end of every revolution. New
  setting `[Effects] AnimLoopSeamFix = 1`.
- All verified high-FPS fixes are now enabled inside the ASI and no longer need INI
  keys (replacing the ASI alone updates everything). The keys still work as
  kill-switches (`Key = 0`) for troubleshooting; README-EN.txt lists them.
- Analog stick movement is off in the supplied INI (`[Movement] AnalogTiers = 0`):
  with it on, a fully tilted stick runs at the 1.5x / 2x top speed, which made the
  game feel faster than the original. Set it to 1 to use it.
- Removed the `LockFollowPercent` and `LockDeadZoneDegrees` camera settings and
  their tuner sliders: they only acted in a camera mode normal lock-on never uses,
  so they did nothing. Lock-on smoothing is `LockTurnMaxDegPerSec` and
  `LockTurnDeadZoneDegrees`, unchanged. Old INI files with the removed keys keep
  working; the keys are ignored.
## Defaults and updating

60 FPS, desktop resolution, original FOV, modern camera, PartySceneFix enabled,
analog movement off. From any 0.5.x: replacing the ASI is enough; old INIs keep
working (their fix keys are accepted, removed keys ignored). No launcher
replacement is included.

## Validation and limits

Both fixes were verified in-game: the summon timer at 90 FPS (exactly two
minutes, counter trace at 30 steps per second) and the save point at 120 FPS.
The summon fix is independent of the Eidolon and of the party slot. Everything
stated for 0.5.8 and 0.5.9 still applies: of the 17 partial-party cutscene
profiles only the First Battle of Judecca boss introduction has been verified
in-game; the death-screen darkening at 2560x1440 and the short mission-start
title card remain. Choose a frame cap your PC can sustain.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
