FF TYPE-0 HD TOOLBOX 0.5.12
FINAL FANTASY TYPE-0 HD for Windows (Steam).
https://www.nexusmods.com/finalfantasytype0hd/mods/4

INSTALLATION
1. Close the game. In Steam, open Properties > Installed Files > Browse.
   This opens the game root containing fftype0hdlauncher.exe and WIN.
2. In the original game launcher, select 1920x1080 and apply your settings.
   This is the resolution entry the mod overrides. Close the game afterwards.
3. Back up any existing mod files and your FFT0HD Unlocker.ini.
4. Copy the archive's WIN folder into the game root, merging folders.
   These four files must be beside WIN\fftype0hd.exe:
   FFT0HD Unlocker.asi, FFT0HD Unlocker.ini, d3d11.dll, keystone.dll.
   Do not create a second WIN folder inside the existing WIN folder.
5. Launch through Steam as usual.

This package contains the main mod only. No launcher replacement is included.
If another mod supplies d3d11.dll, check its loader setup before replacing it.
An optional launcher installed from an earlier release is not updated by this ZIP.

DEFAULT SETTINGS
60 FPS, primary display's current resolution, FOV 100% (original); it widens by
3% during fast camera turns and by up to 50% at the steepest up/down camera
angles (DynamicFOVPercent, PitchFOVPercent). The modern camera is enabled,
TuneWindow off, basic support logging on. All high-FPS fixes are built into the
ASI and always active above 30 FPS; the INI only holds preferences. Analog
stick movement is OFF by default (original fixed speed with L3 cycling); set
[Movement] AnalogTiers = 1 to enable it. The experimental cutscene fix is
ENABLED: [Cutscenes] PartySceneFix = 1. The EXP multiplier is OFF:
[Gameplay] ExpMultiplier = 1.

CUTSCENE FIX - EXPERIMENTAL
Handles 17 reviewed scenes with party-size restrictions. Where needed, empty
party slots receive temporary actors with scene-specific animations. Existing
defeated actors are retained. The mod does not revive party members or change HP.
An empty slot is filled by another available hero; the missing character's own
identity is not restored.

The Judecca final-boss introduction (First Battle of Judecca) was tested at
120 FPS with Queen alive, one empty slot and one defeated participant. Other
supported scenes have only passed script analysis and automated checks, not an
in-game test. This is not a fix for every skipped quest scene or NG+ condition.
See the mod page for coverage and limitations.

To disable it, set PartySceneFix = 0 in [Cutscenes]. Older experimental builds
used JudeccaFullPartyScenes and JudeccaStandIns. They are not in the supplied INI
and are not needed; if an old INI still has them, set them to 0 or delete them.

EXP MULTIPLIER (OPTIONAL)
[Gameplay] ExpMultiplier multiplies all EXP the party earns (kills and
rewards). 1 = original (default); for example, 5 = five times faster leveling.
Levels that the story sets by itself are not affected. Restart the game after
changing the value.

WHAT IS NEW IN 0.5.12
- Enemies no longer turn to face you faster than at 30 FPS. Their scripted turns
  (for example re-aiming during an attack wind-up) ran two times faster at 60 FPS
  and four times faster at 120 FPS, which read as "enemies occasionally speed up".
  [Movement] EnemyTurnFullRate, the 0.5.2 workaround that caused it, is now off
  by default; AiEventKeepFix covers the Qator freeze it was added for. Verified
  in-game at 120 FPS (Qator and the Togoreth stairwell commander).
- Hit-stop, stun build-up and knock-down last as long as at 30 FPS. These timers
  counted rendered frames, so at 60 FPS an enemy (and your character) froze after
  a hit for half the time, the stun gauge drained twice as fast and a knocked-down
  enemy got up after 1 s instead of 2; at 120 FPS a quarter of all that. Built in
  ([Effects] ActorTimerFix = 0 turns it off). Verified in-game at 60 FPS.
- New support diagnostics, off by default: [Diagnostics] TraceEnemySpeed,
  TraceMotionSpeed, TraceActorTimers.

UPDATING FROM ANY 0.5.x
Replace WIN\FFT0HD Unlocker.asi. That is enough: every fix is built in.
Your old INI keeps working; keys it still lists (fix switches, removed camera
keys, legacy Judecca keys) are accepted or ignored. To get the new defaults,
use the supplied INI and transfer your FPS/FOV/camera preferences into it.
If you previously used analog movement, keep AnalogTiers = 1 in your INI.
INIs from 0.5.7-0.5.9 have AnalogTiers = 1 (analog movement on); set it to 0
for the original movement. INIs from 0.5.7 have no [Cutscenes] PartySceneFix;
add PartySceneFix = 1 to use the cutscene fix.
To use the EXP multiplier with an old INI, add the [Gameplay] section from the
supplied INI.
If your INI has EnemyTurnFullRate = 1 (only if you added it yourself), remove it
or set it to 0 to get the turn fix.

ADVANCED: DISABLING A SINGLE FIX
For troubleshooting, any built-in fix can be switched off by adding its key
with the value 0 to the named section (do not add them otherwise):
[Movement] ScriptSpeedPerFrame, MotionStartWaitFix, DodgeCadenceFix, MpRegenFix,
ScriptMotionEventFix, WalkLegMinTicksFix, AiEventKeepFix, AiCountdownFix,
TurnPhaseFullRate, AnalogGlobalsFix
[Effects] FirstFrameFix, TurretFireRateFix, SummonTimerFix, MessageTimerFix,
CameraAnimRateFix, CharAnimRateFix, AnimQuatAlignFix, HitDedupPerVictim, ActorTimerFix
EnemyTurnFullRate is off by default since 0.5.12; 1 brings back the fast enemy turns.
Linked keys: AiEventKeepFix = 0 also turns off ScriptMotionEventFix;
AnimQuatAlignFix = 0 also turns off CharAnimRateFix. AnalogGlobalsFix applies only with AnalogTiers = 1.
ScriptVarDedupAll and ScriptWaitFrameFix are not listed on purpose: 0 brings back
older behaviour with known problems (for example the chapter 3 mission 2 hang).

DISPLAY AND PERFORMANCE
Set FpsCap to 60, 90 or 120 under [OverrideFramerate], using a cap your PC can hold.
The game may slow down if performance falls below the selected cap.
For a fixed resolution, set UseDesktopResolution = 0 and edit ResX/ResY.
The original launcher must still have 1920x1080 selected. Its High/Ultra AA
settings use supersampling and can be expensive at high resolutions.

UNINSTALL
Remove the four Toolbox files from WIN, or restore your backed-up versions.
Preserve d3d11.dll if it is needed by other mods using the same ASI loader.

BUG REPORTS
Include chapter/mission, FPS, party composition, reproduction steps and
WIN\FFT0HD Unlocker.log. The death-screen darkening issue remains unresolved.
No full-campaign or all-party-compositions guarantee is claimed.
