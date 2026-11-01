"""dataring_scan.py <ini>_dataring_N.bin [--rate LO HI] [--top N]
List .data values that were idle, ran for a moment and went idle again inside a [Diagnostics]
DataRing capture (60 snapshots x 100 ms, saved with F9). A HUD timer counted per RENDERED frame
changes by ~fps/10 per snapshot while it runs (12 at 120 FPS), a 30 Hz one by ~3.
Output: type, VA, active window (seconds before the F9 press), start/end values, median step per
snapshot and rate per second, then the whole series."""
import struct
import sys

import numpy as np

args = [a for a in sys.argv[1:] if not a.startswith('--')]
opts = sys.argv[1:]
rate_lo, rate_hi = 20.0, 1000.0
if '--rate' in opts:
    i = opts.index('--rate')
    rate_lo, rate_hi = float(opts[i + 1]), float(opts[i + 2])
    args = [a for a in args if a not in (opts[i + 1], opts[i + 2])]
top = 60
if '--top' in opts:
    top = int(opts[opts.index('--top') + 1])
    args = [a for a in args if a != str(top)]

raw = open(args[0], 'rb').read()
magic, version, count, rva, size, interval, fps, _ = struct.unpack_from('<4sIIIIIfI', raw, 0)
assert magic == b'DRNG', magic
stamps = np.frombuffer(raw, dtype=[('t', '<u8'), ('f', '<u4'), ('p', '<u4')], count=count, offset=32)
data = np.frombuffer(raw, dtype=np.uint8, count=count * size, offset=32 + 16 * count).reshape(count, size)
t = (stamps['t'].astype(np.int64) - int(stamps['t'][-1])) / 1000.0
span = (t[-1] - t[0]) / max(count - 1, 1)
frames = stamps['f'].astype(np.int64)
render_fps = (frames[-1] - frames[0]) / (t[-1] - t[0]) if frames[-1] > frames[0] else float('nan')
print(f'{count} snapshots every {span * 1000:.0f} ms, .data VA {0x140000000 + rva:#x} size {size:#x}, '
      f'fps cap {fps:.0f}, measured render fps {render_fps:.1f}')

IDLE = 3  # identical snapshots required before and after the active window
CHUNK = 1 << 18
results = []
for name, dtype, width in (('u32', '<u4', 4), ('u16', '<u2', 2), ('u8', 'u1', 1), ('f32', '<f4', 4)):
    n = size // width
    view = data[:, :n * width].view(dtype).reshape(count, n)
    kept = []
    for lo in range(0, n, CHUNK):
        part = view[:, lo:lo + CHUNK]
        changed = part[1:] != part[:-1]
        if name == 'f32':
            # small integers read as floats are denormals; those belong to the integer views
            sane = np.isfinite(part) & (np.abs(part) < 1e7) & ((part == 0) | (np.abs(part) > 1e-20))
            changed &= sane[1:] & sane[:-1]
        anyc = changed.any(axis=0)
        first = np.argmax(changed, axis=0)
        last = changed.shape[0] - 1 - np.argmax(changed[::-1], axis=0)
        nchg = changed.sum(axis=0)
        active = last - first + 1
        keep = anyc & (first >= IDLE) & (last <= changed.shape[0] - 1 - IDLE) & (nchg >= 3) & (nchg >= 0.6 * active)
        for k in np.nonzero(keep)[0]:
            kept.append((lo + k, first[k], last[k]))
    for idx, f0, l0 in kept:
        s = view[:, idx].astype(np.float64)
        steps = np.diff(s[f0:l0 + 2])
        body = steps[1:-1] if steps.size > 3 else steps  # drop the set/reset jumps at both ends
        body = body[body != 0]
        if body.size == 0:
            continue
        med = float(np.median(body))
        rate = abs(med) / span
        mono = bool(np.all(body > 0) or np.all(body < 0))
        if name == 'f32':
            if not mono:  # fades/progress values: no rate window, but they must run one way
                continue
        elif not (rate_lo <= rate <= rate_hi):
            continue
        returns = s[0] == s[-1]
        results.append((not returns, not mono, -rate, name, rva + idx * width, t[f0 + 1], t[l0 + 1],
                        s[0], s[-1], med, rate, s))

# one line per value: a u32 hit hides the u16/u8 views of its low bytes, an f32 hit hides the integer
# views of its bytes
taken = {}
for r in results:
    taken.setdefault(r[4], set()).add(r[3])
def shadowed(r):
    name, off = r[3], r[4]
    if name == 'f32':
        return False
    if any('f32' in taken.get(off - k, ()) for k in range(4)):
        return True
    if name == 'u16':
        return 'u32' in taken.get(off, ())
    if name == 'u8':
        return 'u32' in taken.get(off, ()) or 'u16' in taken.get(off, ())
    return False
results = [r for r in results if not shadowed(r)]
results.sort(key=lambda r: r[:3])
print(f'{len(results)} candidates (idle -> active -> idle, rate {rate_lo:g}..{rate_hi:g}/s); '
      f'first: back to the start value and monotonic, fastest first')
for r in results[:top]:
    _, _, _, name, off, t0, t1, v0, v1, med, rate, s = r
    series = ' '.join(f'{v:g}' for v in s)
    print(f'{name} {0x140000000 + off:#x}  active {t0:+.1f}..{t1:+.1f} s  {v0:g} -> {v1:g}  step {med:+g}/snap '
          f'({rate:.0f}/s)  [{series}]')
