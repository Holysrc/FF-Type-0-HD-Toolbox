# FF Type-0 HD Toolbox 0.5.7

High-FPS gameplay fixes, smoother lock-on camera and optional launcher skip.
Changes since 0.5.6:

- Fixed the chapter 5 Judecca turret firing too quickly above 30 FPS. At 120 FPS,
  its firing interval is now about 233 ms instead of 58 ms, matching the original pace.
- Fixed excessive white flashes from the turret's muzzle effects at high FPS.
- Corrected repeated dodge timing and distance at high FPS, preserving the game's
  original differences between armed and unarmed movement.
- Corrected the accelerated MP restoration rate at high FPS.
- Fixed Supersoldier Akkad stopping during his chapter 4 pursuit at high FPS.
- Fixed a reproduced Vajra scripted movement stall in chapter 4 by preserving
  animation events that scripts could miss between frames. Added further safeguards
  for short scripted walking movements and animation-event waits.
- Added a configurable turn-speed limit and softer framing for the lock-on camera,
  reducing abrupt camera swings around nearby enemies. Available in the live camera tuner.
- Added automatic use of the primary display's current resolution.
- Included an optional launcher replacement: Steam can start the game directly.
  Hold Shift at launch to open the original settings launcher, or disable
  SkipLauncher in the INI. The optional component requires a separate installation.

## Updating

Back up your existing FFT0HD Unlocker.ini before updating. The supplied INI enables
the new fixes, uses the primary display's resolution and defaults to 60 FPS.
Copy your preferred FPS, FOV, camera and movement settings into the new INI.
If you keep your old INI instead, follow the merge list in README-EN.txt; replacing
the ASI alone will leave several new fixes disabled.

## Scope and known issues

The affected gameplay scenarios were tested at 120 FPS; the turret was also checked
against the native 30 FPS reference. This is not a complete campaign regression pass.
The mission-start title card can still disappear too quickly at high FPS, and some
high-FPS steering/camera issues remain. Choose a frame cap your PC can sustain:
the game can slow down when it cannot reach the configured cap.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
