# What this fork adds

This is a fork of [Banz99/Final-Fantasy-Type-0-Hd-Unlocker](https://github.com/Banz99/Final-Fantasy-Type-0-Hd-Unlocker) —
the mod that unlocks custom resolutions, high framerates and FOV in Final Fantasy Type-0 HD on PC.
Everything from the original mod still works exactly the same. This fork adds the things below.
No game files are touched — all changes happen in memory while the game runs, so Steam updates
and file checks never break anything.

## Skip the whole intro

Tired of the autosave notice, three logo screens and six minutes of opening movies every launch?
Add this to `FFT0HD Unlocker.ini` and you go from double-click to the main menu in a few seconds,
hands free:

```ini
[Intro]
SkipIntroVideos=1   ; don't play the two opening movies
AutoSkipSplash=1    ; press "OK" on the autosave notice for you
SkipIntroLogos=1    ; skip the three logo screens
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

Форк мода Banz99 для FF Type-0 HD. Всё из оригинала работает как раньше. Добавлено:
пропуск всего вступления (уведомление, логотипы, 6 минут роликов — секция `[Intro]` в ini),
защита от молчаливых вылетов на неожиданных версиях игры (+ лог-файл с причиной),
исправлены тайминги на высоких fps: наложение катсцен, спешащие постановочные сцены
и губы персонажей на 120 fps.

## Credits

All original work by [Banz99](https://github.com/Banz99) and the upstream contributors
(CookiePLMonster, LunaMoo, Keystone Engine, Ultimate ASI Loader). This fork only adds
the changes described above.
