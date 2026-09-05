import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import os as _os
# dump path: $FFT0_DUMP, else ../../dump/image.bin next to this repo, else ./image.bin
_IMGP = _os.environ.get("FFT0_DUMP") or (_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin") if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin")) else "image.bin")

IMGP = _IMGP
IMG = open(IMGP, "rb").read()
BASE = 0x140000000
TEXT_START, TEXT_END = 0x1000, 0x5A0000  # generous .text range

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def find_refs(target_rvas):
    """Find rip-relative references to any target rva. Returns {target: [(va, mnemonic, op_str)]}"""
    targets = set(target_rvas)
    out = {t: [] for t in targets}
    # scan for 4-byte disp candidates: disp at offset o means insn ends at o+4 (no imm) or o+4+immlen
    for o in range(TEXT_START, TEXT_END - 4):
        v = struct.unpack_from("<i", IMG, o)[0]
        for extra in (0, 1, 2, 4):  # trailing immediate lengths
            t = o + 4 + extra + v
            if t in targets:
                # disassemble a window ending validation: try starts from o-4 back to o-12
                for back in range(3, 13):
                    start = o - back
                    if start < 0: continue
                    insns = list(md.disasm(IMG[start:o+4+extra], BASE + start, 2))
                    if not insns: continue
                    insn = insns[0]
                    if insn.size != back + 4 + extra: continue
                    ok = False
                    for op in insn.operands:
                        if op.type == 3 and op.mem.base == 41:
                            if insn.address + insn.size + op.mem.disp == BASE + t:
                                ok = True
                    if ok:
                        out[t].append((insn.address, insn.mnemonic, insn.op_str))
                        break
    return out

if __name__ == "__main__":
    rvas = [int(a, 16) - BASE for a in sys.argv[1:]]
    res = find_refs(rvas)
    for t, refs in sorted(res.items()):
        print(f"--- refs to {hex(BASE + t)} ({len(refs)}) ---")
        seen = set()
        for va, mn, ops in sorted(refs):
            if va in seen: continue
            seen.add(va)
            print(f"  {hex(va)}: {mn} {ops}")
