"""Verify turret hook boundaries and execute its actual x64 cooldown code on Windows.

Requires capstone, keystone-engine and dump/image.bin (or --dump PATH).
Also summarizes existing TraceWeapon captures as projectile lifetimes, not shots.
"""
import argparse
import collections
import ctypes
from pathlib import Path
import re

import capstone
import keystone


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump', type=Path, default=root / 'dump/image.bin')
    args = parser.parse_args()
    data = args.dump.read_bytes()
    source = (root / 'source/Patch.cpp').read_text(encoding='utf-8')
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    for var, address, length in [('tc', 0x2d2e82, 26), ('tf', 0x2d2e31, 9)]:
        sig = re.search(r'auto ' + var + r' = FindOne\("([^"]+)"\)', source)[1]
        regex = b''.join(b'.' if x == '?' else re.escape(bytes([int(x, 16)]))
                         for x in sig.split())
        hits = [m.start() for m in re.finditer(regex, data, re.DOTALL)]
        assert hits == [address], (var, hits)
        instructions = list(md.disasm(data[address:address + length], address))
        assert sum(i.size for i in instructions) == length
        print(f'{var}: unique RVA {address:X}, {length}-byte instruction boundary OK')
    assert data[0x2d2e9c:0x2d2e9e] == b'\x89\x0d'  # original counter store retained

    asm = re.search(r'kTurretCooldownAsm = "([^"]+)"', source)[1]
    # Mirror the mod's instruction-by-instruction Keystone pass as well as full assembly.
    for instruction in asm.replace('$0', '28').split(';'):
        if not re.search(r'\bj\w+ A', instruction):
            ks.asm(instruction)
    trace = source[source.index('auto tf = FindOne'):]
    trace = trace[trace.index('ParametricASMJump('):trace.index('tf, 0, 9);')]
    trace_asm = ''.join(re.findall(r'"([^"]*)"', trace)).replace('$0', '0x1234567812345678')
    ks.asm(trace_asm)
    print('Keystone: cooldown and diagnostic trampoline assemble')

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    page = kernel.VirtualAlloc(None, 4096, 0x3000, 0x40)
    if not page:
        raise ctypes.WinError(ctypes.get_last_error())
    step = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int)(page)
    try:
        # Reference is the actual original modulo-7 instructions from the game.
        native = data[0x2d2e82:0x2d2e9c] + bytes(ks.asm('mov eax, ecx; ret')[0])
        ctypes.memmove(page, native, len(native))
        reference = [step(i) for i in range(7)]
        assert reference == [1, 2, 3, 4, 5, 6, 0]
        for fps in [30, 40, 59, 60, 75, 90, 120, 144, 165, 240]:
            period = int(7 * fps / 30 + 0.5)
            code = bytes(ks.asm(asm.replace('$0', str(period)) + '; mov eax, ecx; ret')[0])
            ctypes.memmove(page, code, len(code))
            if fps == 30:
                assert [step(i) for i in range(7)] == reference
            counter = 0
            shots = []
            for frame in range(period * 100):
                if counter == 0:
                    shots.append(frame)
                counter = step(counter)
                assert 0 <= counter < period
            assert shots == list(range(0, period * 100, period))
            assert abs(period / fps - 7 / 30) <= 0.5 / fps + 1e-9
            # Releasing fire lets a nonzero cooldown finish, then leaves zero ready.
            counter = step(0)
            for _ in range(period * 2):
                if counter:
                    counter = step(counter)
            assert counter == 0
            print(f'{fps} FPS: immediate first shot; {period} renders = {period * 1000 / fps:.3f} ms; release/repress OK')
    finally:
        kernel.VirtualFree(page, 0, 0x8000)

    for name in ['weap_120_20260919', 'weap30b_20260919']:
        log = root / 'dump/vajra_test' / name / 'FFT0HD Unlocker.log'
        if not log.exists():
            continue
        previous, starts = {}, []
        for line in log.read_text().splitlines():
            match = re.search(r'\[Weap\] f=(\d+) idx=(\d+) ph=(\d+) clip=500D shot=(\d+)', line)
            if not match:
                continue
            frame, slot, phase, age = map(int, match.groups())
            if slot not in previous or age < previous[slot][1] or (phase == 0 and previous[slot][0] != 0):
                starts.append(frame)
            previous[slot] = (phase, age)
        intervals = collections.Counter(b - a for a, b in zip(starts, starts[1:]))
        print(f'{name}: {len(starts)} projectile starts, observed intervals {dict(intervals)}')
    print('PASS (static/native-code checks; in-game replay still required)')


if __name__ == '__main__':
    main()
