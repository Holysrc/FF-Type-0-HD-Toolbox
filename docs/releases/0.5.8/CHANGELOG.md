# FF Type-0 HD Toolbox 0.5.8

Partial-party cutscenes and temporary cinematic participants.
Changes since 0.5.7:

- Added an experimental fix for 17 reviewed cutscenes that can be skipped when
  fewer than three party members are alive. The fix changes only identified
  cutscene eligibility checks, preserving ordinary gameplay party counts.
- Added temporary cinematic participants for empty party slots in scenes that
  use the combat party. Required animations are loaded for each supported scene,
  and the temporary actors are removed by the game's scene cleanup.
- Preserved the native casting in scenes that create their own actors, and
  preserved other scenes' existing one-/two-/three-participant staging.
- Fixed an animation wait on an empty party placeholder that could stall the
  Judecca boss introduction when forcing that scene to play.
- Added optional diagnostics for cutscene state and death-overlay investigation.
  These detailed diagnostics are disabled in the supplied configuration.

## Defaults and updating

The new `[Cutscenes] PartySceneFix = 1` is enabled in the supplied INI and is
experimental. If keeping an older INI, merge the setting into its Cutscenes
section; replacing only the ASI will not enable this feature. See README-EN.txt.
The clean preset retains 60 FPS, desktop resolution and original FOV.
No launcher replacement is included in this package.

## Validation and limits

The final-boss introduction in First Battle of Judecca (scene 7555) was tested
at 120 FPS with Queen alive, one empty slot and one defeated party member.
All six required animations played, the scene completed and battle began.
Logs confirmed removal of the temporary actor; party entries and HP were
unchanged. This is not a full campaign test: the other 16 scene profiles have
script analysis and automated checks, but no in-game verification yet.

Coverage: 7156,7157,7158,7159,7301,7355,7452,7453,7455,7458,7459,7551,7553,
7554,7555,7558,7752. The fix does not restore every missable quest scene or
alter recruitment/NG+ story flags. An empty slot receives a distinct fallback
character; the mod does not recover that slot's former identity.

The repeated death-screen darkening reported at 2560x1440 is not fixed.
Previously documented high-FPS limitations remain, including the short
mission-start title card. Choose a frame cap your PC can sustain to avoid
game slowdown.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
