import struct, sys, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import os as _os
# dump path: $FFT0_DUMP, else ../../dump/image.bin next to this repo, else ./image.bin
_IMGP = _os.environ.get("FFT0_DUMP") or (_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin") if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin")) else "image.bin")

IMGP = _IMGP
IMG = open(IMGP, "rb").read()
BASE = 0x140000000
RTBASE = 0x7FF7ECD90000
PDATA_START, PDATA_SIZE = 0x9ee000, 0x3e328

funcs = []
for off in range(PDATA_START, PDATA_START + PDATA_SIZE, 12):
    b, e, u = struct.unpack_from("<III", IMG, off)
    if b == 0: break
    funcs.append((b, e))
funcs.sort()

def func_of(rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, e = funcs[mid]
        if rva < b: hi = mid - 1
        elif rva >= e: lo = mid + 1
        else: return b, e
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def annotate(insn):
    note = ""
    for op in insn.operands:
        try:
            if op.type == 3 and op.mem.base == 41:  # X86_OP_MEM, rip
                tgt = insn.address + insn.size + op.mem.disp
                trva = tgt - BASE
                if 0 <= trva < len(IMG) - 8:
                    raw = IMG[trva:trva+8]
                    f32 = struct.unpack("<f", raw[:4])[0]
                    i32 = struct.unpack("<i", raw[:4])[0]
                    q = struct.unpack("<Q", raw)[0]
                    s = ""
                    m = re.match(rb"[\x20-\x7e]{4,}", IMG[trva:trva+32])
                    if m: s = " str=" + repr(m.group()[:24])
                    ptr = ""
                    if RTBASE <= q < RTBASE + 0xa8c000:
                        ptr = f" ptr->{hex(BASE + q - RTBASE)}"
                    note += f"  ; [{hex(tgt)}] f32={f32:.6g} i32={i32}{s}{ptr}"
        except Exception:
            pass
    return note

def disasm(va, maxinstr=400):
    rva = va - BASE
    fb = func_of(rva)
    if fb:
        b, e = fb
        print(f"=== function {hex(BASE+b)}..{hex(BASE+e)} (size {e-b}) containing {hex(va)} ===")
    else:
        b, e = rva, min(rva + 0x200, len(IMG))
        print(f"=== no pdata entry, raw window at {hex(va)} ===")
    count = 0
    for insn in md.disasm(IMG[b:e], BASE + b):
        mark = ">>" if insn.address == va else "  "
        print(f"{mark} {hex(insn.address)}: {insn.mnemonic} {insn.op_str}{annotate(insn)}")
        count += 1
        if count >= maxinstr:
            print("... (truncated)")
            break

if __name__ == "__main__":
    for a in sys.argv[1:]:
        disasm(int(a, 16))
        print()
