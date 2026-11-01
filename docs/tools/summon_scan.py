"""summon_scan.py <ini>_summon_N.bin  - find monotonically decreasing fields in TraceSummon snapshots.
Record layout (see StartSummonTraceWatcher in Patch.cpp): header {u32 tickMs, u32 ch, u64 actor,
u32 class, u32 frame}, then regions actor 0x1000, aiblock 0x5a8, battle 0x800 (0x658800),
party 0x2000 (0x740000), tbl 0x400 (0x655C00), entry0/1/2 0x100 each."""
import struct, sys
REGIONS = [('actor', 0x1000), ('aiblock', 0x5a8), ('battle', 0x800), ('party', 0x2000), ('tbl', 0x400), ('entry0', 0x100), ('entry1', 0x100), ('entry2', 0x100)]
HDR = struct.Struct('<IIQII')
data = open(sys.argv[1], 'rb').read()
rec = HDR.size + sum(s for _, s in REGIONS)
n = len(data) // rec
print(f'{n} samples, record {rec} bytes')
samples = []
for i in range(n):
    off = i * rec
    tick, ch, actor, cls, frame = HDR.unpack_from(data, off)
    off += HDR.size
    regs = {}
    for name, size in REGIONS:
        regs[name] = data[off:off + size]; off += size
    samples.append((tick, frame, regs))
t0, t1 = samples[0][0], samples[-1][0]
print(f'time {t0} .. {t1} ms ({(t1 - t0) / 1000:.1f} s), frames {samples[0][1]} .. {samples[-1][1]}')
minRate = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
def scan(name, size, fmt, width):
    st = struct.Struct(fmt)
    for o in range(0, size - width + 1, 2 if width == 2 else 4):
        vals = [st.unpack_from(s[2][name], o)[0] for s in samples]
        if fmt == '<f' and any(v != v or abs(v) > 1e9 for v in vals): continue
        dec = all(b <= a for a, b in zip(vals, vals[1:]))
        inc = all(b >= a for a, b in zip(vals, vals[1:]))
        if (not dec and not inc) or vals[0] == vals[-1]: continue
        changes = sum(1 for a, b in zip(vals, vals[1:]) if a != b)
        if changes < max(3, n // 4): continue  # must move on most samples, not a one-off
        rate = (vals[-1] - vals[0]) / ((t1 - t0) / 1000.0)
        if abs(rate) < minRate: continue
        print(f'{name}+{o:04X} {fmt:>3} {"dec" if dec else "inc"} {vals[0]} -> {vals[-1]}  rate {rate:+.2f}/s  changes {changes}/{n - 1}  first {vals[:6]}')
for name, size in REGIONS:
    scan(name, size, '<i', 4); scan(name, size, '<h', 2); scan(name, size, '<f', 4)
