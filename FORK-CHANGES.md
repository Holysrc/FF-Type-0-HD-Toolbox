# FF Type-0 HD Toolbox — what it adds

This project started as a fork of [Banz99/Final-Fantasy-Type-0-Hd-Unlocker](https://github.com/Banz99/Final-Fantasy-Type-0-Hd-Unlocker) —
the mod that unlocks custom resolutions, high framerates and FOV in Final Fantasy Type-0 HD on PC.
Everything from the original mod still works exactly the same. The toolbox adds the things below.
No game files are touched — all changes happen in memory while the game runs, so Steam updates
and file checks never break anything.

## Skip the whole intro

Tired of the autosave notice, three logo screens and six minutes of opening movies every launch?
Add this to `FFT0HD Unlocker.ini` and you go from double-click to the main menu in a few seconds,
hands free:

```ini
[Intro]
SkipIntroVideos=1   ; don't play the two opening movies
AutoSkipSplash=1    ; auto-confirm the autosave notice and flip through the logo screens
```

## Modern camera

The stock camera turns at one constant speed and can't be tuned per axis — it feels stiff,
like the PSP game it came from. The `[Camera]` ini section makes it behave like a modern
third-person game:

- **Camera distance** beyond the launcher's "Far" (separately for normal play and lock-on).
- **Separate turn speeds** for left/right and up/down (the game shares one speed for both).
- **Stick response curve**: most of the stick travel is a calm, precise "slow zone", the last
  bit ramps to full speed — with adjustable zone size, zone speed and start smoothness.
  Diagonals count as full deflection on both axes, so circling a target feels right.
- **Dynamic field of view**: the view widens slightly during fast turns and when looking
  steeply up or down, which adds a lot to the modern feel.
- **Live tuning window** (`TuneWindow=1`): a small always-on-top window with a slider for
  every value above — drag or type a number, see the result instantly in-game, hover a
  slider for a plain-language explanation, then hit "Save to ini". Works best with the game
  in windowed or borderless mode.

The shipped defaults are tuned for a **gamepad**. Mouse players: the defaults leave the mouse
mostly stock — open the tuning window and pick your own numbers.

## Analog movement (new in 0.5)

In the stock game how far you tilt the left stick doesn't matter — you always move at one
of three fixed speeds cycled by clicking the stick (L3). The `[Movement]` ini section makes
movement fully analog, like any modern game:

- **Tilt = speed.** The multiplier slides smoothly from a slow stroll (`MinSpeedPercent`,
  default 40% of the normal speed — slower than the game can normally go), through the normal
  speed at `WalkTiltPercent`, up to the top speed at full tilt.
- **L3 picks the top speed.** Clicking the stick toggles the cap between the game's own
  1.5x and 2x boosts, showing the original speed-2/speed-3 icons. The 2x boost is very strong
  in combat (the community rightly calls it near game-breaking), so keeping it a deliberate
  button press preserves the balance — while the 1.5x range keeps towns comfortable.
- Everything runs through the game's own speed system (the same tables, multipliers and
  animation blending the L3 toggle uses), so animations and cutscenes behave exactly like stock.

```ini
[Movement]
AnalogTiers=1        ; 0 = stock 3-speed toggle
MinSpeedPercent=40   ; speed at a barely-tilted stick, % of normal
WalkTiltPercent=80   ; tilt that gives exactly the normal speed
SprintTiltPercent=95 ; tilt that gives the top (L3-chosen) speed
```

## The game no longer crashes silently on startup

With the original mod, if your game version was slightly different from the one the mod expects,
the game could just close to desktop with no message. Now the mod notices the mismatch, writes
what exactly didn't match into a log file (`FFT0HD Unlocker.log`, created next to the ini),
and keeps the game running — you just lose that one feature instead of the whole game.

## Fixed things that ran too fast at 60/120 fps

- **Cutscenes starting on top of each other.** One of the game's internal wait timers ran twice
  as fast at 60 fps (four times at 120), so the next scene could start before the previous one
  finished. Fixed.
- **Staged scenes rushing.** Pauses inside scripted scenes were designed for 30 fps and ran too
  fast at higher framerates. Fixed.
- **Broken lip sync at 120 fps.** The original mod had a fix for lips at 60 fps only; the same
  problem happened at 120. Now fixed for any framerate.
- **Vertical camera speed multiplying with the framerate.** The stick's up/down camera speed
  was never framerate-corrected (not even in the original mod — the code path was unknown), so
  at 120 fps it turned four times too fast. Now it feels the same at any framerate.

## For the curious: diagnostics

There's also a `[Diagnostics]` ini section with optional switches that log what the game is doing
(sounds, movies, opened files and so on). They are all off by default and only useful if you're
hunting a bug — the log file above will tell the story.

## Building from source

Same as the original (`premake5 vs20xx`, build the `Master` configuration). Notes:

- The project file targets premake 5.0.0-beta8, and `premake5 vs2026` works out of the box.
- On the newest Visual Studio 2026 compiler, the `source/Utils` submodule needs two one-line
  fixes (its code predates the current C++ library): in `MemoryMgr.h` replace the two
  `stdext::make_checked_array_iterator(...)` wrappers with the plain pointer, and add
  `#include <string>` at the top of `Patterns.h`. VS 2019/2022 build without changes.

## Кратко по-русски

FF Type-0 HD Toolbox — вырос из форка мода Banz99. Всё из оригинала работает как раньше. Добавлено:
аналоговое движение (секция `[Movement]`: наклон левого стика плавно задаёт скорость — от
медленной прогулки ниже штатной до ускорения; L3 переключает потолок между 1.5x и 2x с
родными иконками),
пропуск всего вступления (уведомление, логотипы, 6 минут роликов — секция `[Intro]` в ini),
современная камера (секция `[Camera]`: дистанция дальше «Far», раздельные скорости осей,
кривая отклика стика как в современных шутерах, динамический FOV от скорости поворота и
наклона, окно живой настройки поверх игры с кнопкой сохранения — `TuneWindow=1`; настройки
по умолчанию подобраны под геймпад), защита от молчаливых вылетов на неожиданных версиях
игры (+ лог-файл с причиной), исправлены тайминги на высоких fps: наложение катсцен,
спешащие постановочные сцены и губы персонажей на 120 fps.

## Credits

All original work by [Banz99](https://github.com/Banz99) and the upstream contributors
(CookiePLMonster, LunaMoo, Keystone Engine, Ultimate ASI Loader). The toolbox adds
the changes described above on top of that foundation.
