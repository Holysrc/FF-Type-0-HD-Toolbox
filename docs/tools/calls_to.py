"""calls_to.py <va> [<va> ...]  - list every E8 call / E9 jmp whose rel32 target is one of the given VAs.
Full linear scan of the dump (no function-boundary assumptions), so it also finds calls that callers.py misses."""
import os, struct, sys
dump = os.environ.get('FFT0_DUMP') or os.path.join(os.path.dirname(__file__), '..', '..', 'dump', 'image.bin')
img = open(dump, 'rb').read()
BASE = 0x140000000
targets = {int(a, 16) - BASE for a in sys.argv[1:]}
text_end = 0x539000
hits = {t: [] for t in targets}
for i in range(0, text_end - 5):
    op = img[i]
    if op == 0xE8 or op == 0xE9:
        rel = struct.unpack_from('<i', img, i + 1)[0]
        t = i + 5 + rel
        if t in hits:
            hits[t].append((i, op))
for t in sorted(hits):
    print(f'--- refs to {BASE + t:#x} ({len(hits[t])}) ---')
    for i, op in hits[t]:
        print(f'  {BASE + i:#x}: {"call" if op == 0xE8 else "jmp"}')
