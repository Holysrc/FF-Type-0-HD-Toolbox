"""scriptdis.py <dump.bin> [start] [end]  - disassemble FFT0 script bytecode dumped by HangWatch
(0x200-byte script object header followed by the code blob; PCs are offsets into the blob).

VM semantics (see GAME_INTERNALS 4a). Statement word low nibble:
  1 control: op=(w>>4)&0xF: 1/2/A "if expr then skip next 4 bytes"; 4 jump label w1; 5 label w1;
             6 if/else chain; 7 skip w1 bytes; C return expr; D end. 4 bytes + inline expr for 1/2/A/C.
  2 command: id=w>>4, w1 = flags/result slot, w2 = arg bytes; args are expression blocks.
  8 call:    fn id = (w>>4)&0x3ff, 10-byte header + w2 arg bytes.
  else       expression statement: header len = w>>4.
Expression operands: 4 const[w>>6]; 5 var(kind=(w>>4)&3, idx=w>>6); 6 operator w>>4; 2 nested cmd; 8 call.
"""
import os, struct, sys
dump_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'dump')
d = open(sys.argv[1], 'rb').read()
hdr, code = d[:0x200], d[0x200:]
codeptr = struct.unpack_from('<Q', hdr, 0x118)[0]
def tbl(off):
    v = struct.unpack_from('<Q', hdr, off)[0]
    return v - codeptr if v else None
T120, T138, T140, T148, T150 = tbl(0x120), tbl(0x138), tbl(0x140), tbl(0x148), tbl(0x150)
image = None
try:
    image = open(os.path.join(dump_dir, 'image.bin'), 'rb').read()
except OSError:
    pass
def cmdindex(opid):
    if image is None: return -1
    return struct.unpack_from('<H', image, 0x659eb0 + opid * 2)[0]
def const(i):
    if T150 is None: return '?'
    return struct.unpack_from('<f', code, T150 + i * 4)[0]
OPS = {0x10: '+', 0x11: '-', 0x0d: '*', 0x0e: '/', 0x0f: '//', 0x12: '<', 0x13: '>', 0x6b: '<=', 0x6c: '>=',
       0x6d: '==', 0x6e: '!=', 0x6f: '==0?', 0x70: '!=0?', 0x17: '=', 0x69: '++', 0x6a: '--', 0x71: '+=', 0x72: '-='}
def w16(pc): return struct.unpack_from('<H', code, pc)[0]

def expr(pc, end, depth=0):
    """decode operands in [pc,end) -> string (RPN shown in order)"""
    out = []
    while pc < end:
        w = w16(pc); t = w & 0xF
        if t == 4: out.append(f'{const(w >> 6):g}'); pc += 2
        elif t == 5: out.append(f'v{(w >> 4) & 3}[{w >> 6}]'); pc += 2
        elif t == 6: out.append(OPS.get(w >> 4, f'op{w >> 4:X}')); pc += 2
        elif t == 3:
            if (w >> 4) > 512 or depth > 8: out.append(f"?{w:04X}"); pc += 2; continue
            sub, pc2 = expr(pc + 2, pc + 2 + (w >> 4), depth + 1); out.append("(" + sub + ")"); pc = pc2
        elif t == 2:
            cid = w >> 4; ln = w16(pc + 4)
            if ln > 512 or depth > 8: out.append(f'?{w:04X}'); pc += 2; continue
            args = expr(pc + 6, pc + 6 + ln, depth + 1)[0]
            out.append(f'CMD{cid:X}[{cmdindex(cid):X}]({args})'); pc += 6 + ln
        elif t == 8:
            fid = (w >> 4) & 0x3ff; ln = w16(pc + 4)
            if ln > 512 or depth > 8: out.append(f'?{w:04X}'); pc += 2; continue
            args = expr(pc + 10, pc + 10 + ln, depth + 1)[0]
            out.append(f'CALL{fid}({args})'); pc += 10 + ln
        elif t == 7: out.append(f'ref{w >> 6}'); pc += 2
        else: out.append(f'?{w:04X}'); pc += 2
    return ' '.join(out), pc

def stmt(pc):
    w = w16(pc); t = w & 0xF
    if t == 1:
        op = (w >> 4) & 0xF; w1 = w16(pc + 2)
        if op in (1, 2, 0xA):
            hw = w16(pc + 4); ln = hw >> 4; e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'IF{op:X} ({e}) else-do-next'
        if op == 4: return pc + 4, f'GOTO label{w1}'
        if op == 5: return pc + 4, f'label{w1}:'
        if op == 7:
            hw = w16(pc + 4); ln = hw >> 4; e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 4 + w1, f'CASE ({e}):'
        if op == 8: return pc + 4, 'ENDSWITCH'
        if op == 3: return pc + 4, f'ELSE-MARK w1={w1}'
        if op == 6:
            hw = w16(pc + 4); ln = hw >> 4; e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'SWITCH ({e}) block-len={w1}'
        if op == 0xC:
            hw = w16(pc + 4); ln = hw >> 4; e, _ = expr(pc + 6, pc + 6 + ln)
            return pc + 6 + ln, f'RETURN ({e})'
        if op == 0xD: return pc + 4, 'END'
        return pc + 4, f'CTRL{op:X} w1={w1}'
    if t == 2:
        cid = w >> 4; w1 = w16(pc + 2); ln = w16(pc + 4); args, _ = expr(pc + 6, pc + 6 + ln)
        res = '' if (w1 >> 2) == 0x3ff else f' -> v[{w1 >> 2}]' if (w1 & 3) else f' -> id{w1 >> 2}'
        return pc + 6 + ln, f'CMD{cid:X}[{cmdindex(cid):X}]({args}){res}'
    if t == 8:
        fid = (w >> 4) & 0x3ff; ln = w16(pc + 4); args, _ = expr(pc + 10, pc + 10 + ln)
        return pc + 10 + ln, f'CALL{fid}({args})  hdr={code[pc:pc + 10].hex(" ")}'
    ln = w >> 4
    e, _ = expr(pc + 2, pc + 2 + ln)
    return pc + 2 + ln, f'EXPR{t:X} ({e})'

start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
print(f'tables: fn@{T120:#x} t138@{T138:#x} t140@{T140:#x} labels@{T148:#x} consts@{T150:#x}')
pc = start
while pc < end:
    npc, text = stmt(pc)
    print(f'{pc:6d}: {text}    ; {code[pc:min(npc, pc + 14)].hex(" ")}')
    if npc <= pc: pc += 2
    else: pc = npc
