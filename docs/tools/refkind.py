import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import os as _os
# dump path: $FFT0_DUMP, else ../../dump/image.bin next to this repo, else ./image.bin
_IMGP = _os.environ.get("FFT0_DUMP") or (_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin") if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin")) else "image.bin")
IMG = open(_IMGP, "rb").read()
BASE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def classify(disp_off):
    """disp_off = file offset where the imm32 displacement value sits; find the instruction containing it."""
    for back in range(3, 14):
        start = disp_off - back
        insns = list(md.disasm(IMG[start:disp_off+12], BASE+start, 1))
        if not insns: continue
        insn = insns[0]
        if insn.address + insn.size < BASE + disp_off + 4: continue
        # check operand mem disp matches
        for op in insn.operands:
            if op.type == 3 and op.value.mem.disp in (TARGET,):
                acc = []
                if op.access & 1: acc.append("R")
                if op.access & 2: acc.append("W")
                return insn, "".join(acc)
    return None, None

targets = [int(a,16) for a in sys.argv[1:]]
for T in targets:
    TARGET = T
    pat = struct.pack("<i", T)
    idx = IMG.find(pat)
    print(f"=== disp {hex(T)} ===")
    while idx != -1:
        if idx < 0x5A0000:
            insn, acc = classify(idx)
            if insn:
                print(f"  {hex(insn.address)}: [{acc}] {insn.mnemonic} {insn.op_str}")
        idx = IMG.find(pat, idx+1)
