"""Read installed event resources and inventory native CMD5F party-count checks.

Read-only access to game packs. Extracted assets and reports stay under dump/.
Usage: python docs/tools/audit_cutscene_gates.py --package <JP/package>
Index layout verified against installed resources and scene7553 runtime bytes.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'dump/cutscene_audit'


def u32(b, off):
    return struct.unpack_from('<I', b, off)[0]


def atels(blob):
    """Locate plausible ATELY modules; offset tables must fit in the resource."""
    start = 0
    while True:
        start = blob.find(b'ATELY\0\0\0', start)
        if start < 0:
            return
        b = blob[start:]
        if len(b) >= 40:
            names, table = u32(b, 12), u32(b, 16)
            if 40 <= names < table and table + 8 <= len(b):
                groups, _, functions, labels, constants = struct.unpack_from('<BBHHH', b, table)
                pool = table + 8 + groups * 16 + functions * 24 + labels * 8
                end = pool + constants * 4
                if groups and end <= len(b):
                    yield start, b[:end], pool, names
        start += 8


def inventory(entry, raw):
    result = []
    # Exact no-argument nested CMD5F encoding observed in both Judecca guards.
    needle = bytes.fromhex('F2 05 FC 0F 00 00')
    for offset, code, pool, names in atels(raw):
        for pos in range(40, names - len(needle) + 1, 2):
            if code[pos:pos + 6] != needle:
                continue
            following = code[pos + 6:pos + 10]
            threshold = None
            operator = None
            if len(following) == 4:
                const, op = struct.unpack('<HH', following)
                index = const >> 6
                if const & 15 == 4 and pool + index * 4 + 4 <= len(code):
                    threshold = struct.unpack_from('<f', code, pool + index * 4)[0]
                    operator = hex(op)
            result.append(dict(file=entry['name'], file_id=entry['id'], module=offset,
                               pc=pos + 6, threshold=threshold, operator=operator,
                               window=code[max(0, pos - 6):pos + 80].hex(' ')))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, help='Read installed JP/package; omit to audit cache')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = OUT / 'manifest.json'
    if args.package:
        fnd = (args.package / 'suzaku.fnd').read_bytes()
        fsd = (args.package / 'suzaku.fsd').read_bytes()
        count = u32(fnd, 0)
        assert u32(fsd, 8) == count
        entries = []
        absent = []
        handles = {}
        try:
            for i in range(count):
                p = u32(fnd, 4 + 4 * i)
                name = fnd[p:fnd.index(0, p)].decode('ascii')
                if not name.startswith('JP/event/'):
                    continue
                record = u32(fsd, 16) + i * 56
                size, flags, unpacked, _, offset = struct.unpack_from('<IIIIQ', fsd, record)
                if size == 0 and flags == 0 and offset == 0xFFFFFFFFFFFFFFFF:
                    absent.append(dict(id=i, name=name))
                    continue
                pack = fsd[record + 48]
                assert pack < 10 and size < 16 * 1024 * 1024 and unpacked < 64 * 1024 * 1024
                cache = f'{i}_{Path(name).name}'
                target = OUT / cache
                if not target.exists():
                    if pack not in handles:
                        handles[pack] = (args.package / f'pack{pack}.pac').open('rb')
                    handle = handles[pack]
                    handle.seek(offset)
                    data = handle.read(size)
                    assert len(data) == size
                    raw = zlib.decompress(data, -15) if flags & 2 else data
                    assert not unpacked or len(raw) == unpacked, (name, len(raw), unpacked)
                    target.write_bytes(raw)
                entries.append(dict(id=i, name=name, cache=cache, pack=pack, flags=flags))
        finally:
            for handle in handles.values():
                handle.close()
        manifest.write_text(json.dumps(entries, indent=2), encoding='utf-8')
        (OUT / 'absent.json').write_text(json.dumps(absent, indent=2), encoding='utf-8')
    entries = json.loads(manifest.read_text(encoding='utf-8'))
    checks = []
    modules = 0
    for entry in entries:
        raw = (OUT / entry['cache']).read_bytes()
        modules += sum(1 for _ in atels(raw))
        checks.extend(inventory(entry, raw))
    (OUT / 'party_count_checks.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
    print(f'{len(entries)} resources, {modules} plausible ATELY modules, {len(checks)} CMD5F sites')
    print('Comparisons:', Counter((str(c['threshold']), c['operator']) for c in checks))
    for c in checks:
        print(c['file_id'], c['file'], f"module={c['module']:X} pc={c['pc']:X}", c['threshold'], c['operator'])


if __name__ == '__main__':
    main()
