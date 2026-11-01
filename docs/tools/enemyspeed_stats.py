"""Summarize [EnemySpeed] burst lines of an FFT0HD Unlocker.log per actor class (TraceEnemySpeed=1).

Usage: enemyspeed_stats.py <log> [<log2> ...]   (one table per log; compare 30 vs 60 fps runs side by side)

Per class: bursts, max peak, median peak, run speed = total distance / total duration of bursts that lasted
>= 0.5 s (steady movement, not one-sample lunges), number of such runs, factor values seen at the peaks.
Party channels (ch 0..2, classes < 0x1000) are listed too as the reference: their speed is the player's.
"""
import re, statistics, sys
from collections import defaultdict

RX = re.compile(r"\[EnemySpeed \+(\d+)s\] ch=(\d+) class=([0-9A-F]{4}) burst: peak (\d+) u/s, mean (\d+) u/s, (\d+) units in ([\d.]+) s, factor x([\d.]+) clip=(\d+) hp=(\d+)/(\d+)")

def summarize(path):
    per = defaultdict(list)
    armed = None
    for line in open(path, encoding='utf-8', errors='replace'):
        if '[EnemySpeed] armed' in line:
            armed = line.strip()
        m = RX.search(line)
        if m:
            t, ch, cls, peak, mean, units, dur, factor, clip, hp, hpmax = m.groups()
            per[cls].append(dict(t=int(t), ch=int(ch), peak=int(peak), mean=int(mean), units=int(units),
                                 dur=float(dur), factor=float(factor), clip=int(clip), hp=int(hp), hpmax=int(hpmax)))
    print(f"== {path}")
    print(f"   {armed}")
    print(f"   {'class':6} {'bursts':>6} {'maxpk':>6} {'medpk':>6} {'run u/s':>8} {'runs':>4} {'run dist':>8} {'run time':>8}  factors   channels")
    for cls in sorted(per):
        b = per[cls]
        runs = [x for x in b if x['dur'] >= 0.5]
        dist = sum(x['units'] for x in runs); dur = sum(x['dur'] for x in runs)
        run_speed = dist / dur if dur else 0
        factors = sorted({x['factor'] for x in b})
        chans = sorted({x['ch'] for x in b})
        print(f"   {cls:6} {len(b):6d} {max(x['peak'] for x in b):6d} {int(statistics.median(x['peak'] for x in b)):6d} "
              f"{run_speed:8.0f} {len(runs):4d} {dist:8d} {dur:8.2f}  {','.join(f'x{f:.2f}' for f in factors):9} {chans}")
    # long runs listed individually for the enemy classes: these are the steady approach speeds to compare
    print("   long enemy runs (>= 1.0 s):")
    for cls in sorted(per):
        if int(cls, 16) < 0x1000:
            continue
        for x in per[cls]:
            if x['dur'] >= 1.0:
                print(f"     +{x['t']:3d}s class={cls} ch={x['ch']:2d} mean {x['mean']:4d} peak {x['peak']:4d} u/s  {x['units']:5d} u in {x['dur']:.2f} s  clip={x['clip']} factor x{x['factor']:.2f} hp={x['hp']}/{x['hpmax']}")

for p in sys.argv[1:]:
    summarize(p)


# ---- [EnemyTurn] bursts (facing yaw, TraceEnemyTurnMin) -------------------------------------------------------
RXT = re.compile(r"\[EnemyTurn \+(\d+)s\] ch=(\d+) class=([0-9A-F]{4}) turn: peak (\d+) deg/s, (\d+) deg in ([\d.]+) s \(mean (\d+) deg/s\), factor x([\d.]+) clip=(\d+) hp=(\d+)/(\d+)")

def summarize_turns(path):
    per = defaultdict(list)
    for line in open(path, encoding='utf-8', errors='replace'):
        m = RXT.search(line)
        if m:
            t, ch, cls, peak, deg, dur, mean, factor, clip, hp, hpmax = m.groups()
            per[cls].append(dict(t=int(t), ch=int(ch), peak=int(peak), deg=int(deg), dur=float(dur), mean=int(mean),
                                 factor=float(factor), clip=int(clip), hp=int(hp), hpmax=int(hpmax)))
    if not per:
        print("   (no [EnemyTurn] lines)"); return
    print(f"   turns: {'class':6} {'bursts':>6} {'maxpk':>6} {'medpk':>6} {'med mean':>8} {'big':>4} {'big mean':>8} {'big deg':>8}  (big = turns of >= 90 deg; mean = deg/s over the burst)")
    for cls in sorted(per):
        b = per[cls]
        big = [x for x in b if x['deg'] >= 90]
        big_mean = (sum(x['deg'] for x in big) / sum(x['dur'] for x in big)) if big and sum(x['dur'] for x in big) > 0 else 0
        print(f"          {cls:6} {len(b):6d} {max(x['peak'] for x in b):6d} {int(statistics.median(x['peak'] for x in b)):6d} "
              f"{int(statistics.median(x['mean'] for x in b)):8d} {len(big):4d} {big_mean:8.0f} {sum(x['deg'] for x in big):8d}")
    print("   big enemy turns (>= 90 deg):")
    for cls in sorted(per):
        if int(cls, 16) < 0x1000:
            continue
        for x in per[cls]:
            if x['deg'] >= 90:
                print(f"     +{x['t']:3d}s class={cls} ch={x['ch']:2d} {x['deg']:4d} deg in {x['dur']:.2f} s  mean {x['mean']:5d} peak {x['peak']:5d} deg/s  clip={x['clip']} factor x{x['factor']:.2f} hp={x['hp']}/{x['hpmax']}")

for p in sys.argv[1:]:
    summarize_turns(p)
