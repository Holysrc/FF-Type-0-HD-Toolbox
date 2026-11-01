"""Summarize [ActorTimer] and [EnemyVert] lines of FFT0HD Unlocker.log (TraceActorTimers=1, TraceEnemySpeed=1).
Usage: actortimer_stats.py <log> [<log> ...]"""
import re, statistics, sys
from collections import defaultdict
RXA = re.compile(r"\[ActorTimer \+(\d+)s\] ch=(\d+) class=([0-9A-F]{4}) (\S+) [^:]*: (\d+) -> 0 in ([\d.]+) ms")
RXV = re.compile(r"\[EnemyVert \+(\d+)s\] ch=(\d+) class=([0-9A-F]{4}) vertical: peak (\d+) u/s, up (\d+) down (\d+) in ([\d.]+) s, clip=(\d+) hp=(\d+)/(\d+)")
for path in sys.argv[1:]:
    print(f"== {path}")
    for line in open(path, encoding='utf-8', errors='replace'):
        if 'ActorTimer] armed' in line or 'EnemySpeed] armed' in line: print('  ', line.strip())
    ep = defaultdict(list)
    for line in open(path, encoding='utf-8', errors='replace'):
        m = RXA.search(line)
        if m:
            t, ch, cls, field, start, ms = m.groups()
            side = 'enemy' if int(cls, 16) >= 0x2000 else 'party'
            ep[(side, field, int(start))].append(float(ms))
    print(f"   {'side':6} {'field':5} {'start':>5} {'n':>3} {'median ms':>9} {'ms/unit':>8}  all ms")
    for k in sorted(ep):
        v = ep[k]; med = statistics.median(v)
        print(f"   {k[0]:6} {k[1]:5} {k[2]:5d} {len(v):3d} {med:9.1f} {med / k[2]:8.1f}  {[round(x) for x in sorted(v)][:14]}")
    vb = defaultdict(list)
    for line in open(path, encoding='utf-8', errors='replace'):
        m = RXV.search(line)
        if m:
            t, ch, cls, peak, up, down, dur, clip, hp, hpmax = m.groups()
            vb[cls].append(dict(t=int(t), ch=int(ch), peak=int(peak), up=int(up), down=int(down), dur=float(dur), clip=int(clip)))
    print(f"   vertical: {'class':6} {'bursts':>6} {'maxpk':>6} {'medpk':>6} {'med dur':>7} {'med up':>6} {'med down':>8}")
    for cls in sorted(vb):
        b = vb[cls]
        print(f"             {cls:6} {len(b):6d} {max(x['peak'] for x in b):6d} {int(statistics.median(x['peak'] for x in b)):6d} "
              f"{statistics.median(x['dur'] for x in b):7.2f} {int(statistics.median(x['up'] for x in b)):6d} {int(statistics.median(x['down'] for x in b)):8d}")
    print("   enemy vertical bursts with up+down >= 100 u:")
    for cls in sorted(vb):
        if int(cls, 16) < 0x1000: continue
        for x in vb[cls]:
            if x['up'] + x['down'] >= 100:
                print(f"     +{x['t']:3d}s class={cls} ch={x['ch']:2d} peak {x['peak']:4d} u/s up {x['up']:4d} down {x['down']:4d} in {x['dur']:.2f} s clip={x['clip']}")
