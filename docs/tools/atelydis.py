"""atelydis.py <resource.bin> [module_index] [function_name ...]
Disassemble an ATELY script module from an extracted event resource (dump/cutscene_audit/*.bin),
using the same statement/expression decoding as scriptdis.py (GAME_INTERNALS 4a).
Module layout: 40-byte header (names at +12, table at +16), code from +0x28, table = {u8 groups,
u8, u16 functions, u16 labels, u16 constants}, groups x 16, functions x 24 {u32 id, u32 counts,
8-byte name (inline when shorter than 9 chars, else a hash), u32 start, u32 fill}, labels x 8, then the
float constant pool. A function occupies module [start+0x28, next start+0x28): an 8-byte header, then
statements. PCs printed are module offsets (calibrated on cut7558: getPCModel4 statements at 0x30)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_cutscene_gates import atels

raw = open(sys.argv[1], 'rb').read()
mods = list(atels(raw))
mi = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 0
wanted = [a for a in sys.argv[2:] if not a.isdigit()]
_, module, pool, names = mods[mi]
code = module
table = struct.unpack_from('<I', module, 16)[0]
groups, _, nfunc, nlab, ncon = struct.unpack_from('<BBHHH', module, table)
consts_off = pool

image = None
try:
    image = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'dump', 'image.bin'), 'rb').read()
except OSError:
    pass


def cmdindex(opid):
    if image is None:
        return -1
    return struct.unpack_from('<H', image, 0x659eb0 + opid * 2)[0]


def const(i):
    if i >= ncon:
        return float('nan')
    return struct.unpack_from('<f', code, consts_off + i * 4)[0]


funcs = []
p = table + 8 + groups * 16
for f in range(nfunc):
    fid, counts, n0, n1, start, _ = struct.unpack_from('<IIIIII', module, p)
    nm = struct.pack('<II', n0, n1).split(b'\0')[0]
    name = nm.decode() if nm and all(32 <= c < 127 for c in nm) else f'fn{(fid >> 8) & 0xff:02X}_{n0:08X}'
    funcs.append((start, name, f))
    p += 24
strings = []  # names table: {u16 0x2c, u16 index, u16 offset, u16 length} entries, then the strings
q = names
while q + 8 <= len(module):
    t, i, o, ln = struct.unpack_from('<HHHH', module, q)
    if t != 0x2c or i != len(strings):
        break
    strings.append((o, ln))
    q += 8
strings = [module[q + o:q + o + ln].split(b'\0')[0].decode('latin-1') for o, ln in strings]
labels = {}
for i in range(nlab):
    lid, _, target = struct.unpack_from('<HHI', module, p + i * 8)
    labels[lid] = target
funcs.sort()

OPS = {0x10: '+', 0x11: '-', 0x0d: '*', 0x0e: '/', 0x0f: '//', 0x12: '<', 0x13: '>', 0x6b: '<=', 0x6c: '>=',
       0x6d: '==', 0x6e: '!=', 0x6f: '==0?', 0x70: '!=0?', 0x17: '=', 0x69: '++', 0x6a: '--', 0x71: '+=', 0x72: '-='}


def w16(pc):
    return struct.unpack_from('<H', code, pc)[0] if 0 <= pc <= len(code) - 2 else 0


def expr(pc, end, depth=0):
    out = []
    while pc < end:
        w = w16(pc)
        t = w & 0xF
        if t == 4:
            out.append(f'{const(w >> 6):g}'); pc += 2
        elif t == 5:
            out.append(f'v{(w >> 4) & 3}[{w >> 6}]'); pc += 2
        elif t == 6:
            out.append(OPS.get(w >> 4, f'op{w >> 4:X}')); pc += 2
        elif t == 3:
            if (w >> 4) > 512 or depth > 8:
                out.append(f'?{w:04X}'); pc += 2; continue
            sub, pc2 = expr(pc + 2, pc + 2 + (w >> 4), depth + 1)
            out.append('(' + sub + ')'); pc = pc2
        elif t == 2:
            cid = w >> 4
            ln = w16(pc + 4)
            if ln > 512 or depth > 8:
                out.append(f'?{w:04X}'); pc += 2; continue
            args = expr(pc + 6, pc + 6 + ln, depth + 1)[0]
            out.append(f'CMD{cid:X}[{cmdindex(cid):X}]({args})'); pc += 6 + ln
        elif t == 8:
            fid = (w >> 4) & 0x3ff
            ln = w16(pc + 4)
            if ln > 512 or depth > 8:
                out.append(f'?{w:04X}'); pc += 2; continue
            args = expr(pc + 10, pc + 10 + ln, depth + 1)[0]
            out.append(f'CALL{fid}({args})'); pc += 10 + ln
        elif t == 7:
            r = w >> 6
            out.append(f"ref{r}'{strings[r]}'" if r < len(strings) else f'ref{r}'); pc += 2
        else:
            out.append(f'?{w:04X}'); pc += 2
    return ' '.join(out), pc


def stmt(pc):
    w = w16(pc)
    t = w & 0xF
    if t == 1:
        op = (w >> 4) & 0xF
        w1 = w16(pc + 2)
        if op in (1, 2, 0xA):
            ln = w16(pc + 4) >> 4
            e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'IF{op:X} ({e}) else-skip'
        if op == 4:
            return pc + 4, f'GOTO label{w1} (@{labels.get(w1, -1):X})'
        if op == 5:
            return pc + 4, f'label{w1}:'
        if op == 7:
            ln = w16(pc + 4) >> 4
            e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 4 + w1, f'CASE ({e}):'
        if op == 8:
            return pc + 4, 'ENDSWITCH'
        if op == 3:
            return pc + 4, f'ELSE-MARK w1={w1}'
        if op == 6:
            ln = w16(pc + 4) >> 4
            e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'SWITCH ({e}) block-len={w1}'
        if op == 0xC:
            ln = w16(pc + 4) >> 4
            e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'RETURN ({e})'
        if op == 0xD:
            return pc + 4, 'END'
        return pc + 4, f'CTRL{op:X} w1={w1}'
    if t == 2:
        cid = w >> 4
        w1 = w16(pc + 2)
        ln = w16(pc + 4)
        args, _ = expr(pc + 6, pc + 6 + ln)
        res = '' if (w1 >> 2) == 0x3ff else f' -> v[{w1 >> 2}]' if (w1 & 3) else f' -> id{w1 >> 2}'
        return pc + 6 + ln, f'CMD{cid:X}[{cmdindex(cid):X}]({args}){res}'
    if t == 8:
        fid = (w >> 4) & 0x3ff
        ln = w16(pc + 4)
        args, _ = expr(pc + 10, pc + 10 + ln)
        return pc + 10 + ln, f'CALL{fid}({args})'
    ln = w >> 4
    e, _ = expr(pc + 2, pc + 2 + ln)
    return pc + 2 + ln, f'EXPR{t:X} ({e})'


code_end = names
print(f'module {mi}: {len(module)} bytes, {nfunc} functions, {nlab} labels, {ncon} constants')
for k, (start, name, idx) in enumerate(funcs):
    end = funcs[k + 1][0] + 0x28 if k + 1 < len(funcs) else code_end
    if wanted and name not in wanted:
        continue
    print(f'\nFUNCTION {idx} {name} [{start + 0x30:#x},{end:#x})')
    pc = start + 0x30
    while pc < end:
        npc, text = stmt(pc)
        print(f'{pc:06X}: {text}')
        pc = npc if npc > pc else pc + 2
