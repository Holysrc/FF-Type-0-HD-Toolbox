# FF Type-0 HD Toolbox 0.5.9

Menu text fix for resolutions below 1920x1080.
Changes since 0.5.8:

- Fixed broken menu and dialogue text at resolutions below 1920x1080
  (for example 1280x720 or 1600x900). Letters lost rows and columns of pixels,
  most visibly in Cyrillic text. The problem was introduced in 0.5.7.
  Resolutions of 1920x1080 and above were not affected.

No settings changed. If you already run 0.5.8, replacing the ASI is enough.

## Defaults and updating

Same configuration as 0.5.8: 60 FPS, desktop resolution, original FOV,
`[Cutscenes] PartySceneFix = 1` (experimental). If you come from 0.5.7 or
earlier and keep your old INI, follow the merge lists in README-EN.txt.
No launcher replacement is included in this package.

## Validation and limits

The text fix was confirmed in-game at 1280x720, 90 FPS, with all supplied
fixes enabled. Everything stated for 0.5.8 still applies: of the 17 partial-party
cutscene profiles only the First Battle of Judecca boss introduction (scene 7555)
has been verified in-game; the other 16 rely on script analysis and automated
checks.

Coverage: 7156,7157,7158,7159,7301,7355,7452,7453,7455,7458,7459,7551,7553,
7554,7555,7558,7752. The fix does not restore every missable quest scene or
alter recruitment/NG+ story flags.

The repeated death-screen darkening reported at 2560x1440 is not fixed.
Previously documented high-FPS limitations remain, including the short
mission-start title card. Choose a frame cap your PC can sustain to avoid
game slowdown.

## Credits

Based on Banz99's FFT0HD Unlocker, with contributions and tools from
CookiePLMonster, LunaMoo, Ultimate ASI Loader and Keystone Engine.
