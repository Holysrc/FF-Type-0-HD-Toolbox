import capstone,sys
import os as _os
# dump path: $FFT0_DUMP, else ../../dump/image.bin next to this repo, else ./image.bin
_IMGP = _os.environ.get("FFT0_DUMP") or (_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin") if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin")) else "image.bin")
IMG=open(_IMGP,'rb').read(); BASE=0x140000000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
start=int(sys.argv[1],16); n=int(sys.argv[2]) if len(sys.argv)>2 else 400
off=start-BASE
cnt=0
for insn in md.disasm(IMG[off:off+n], start):
    print(hex(insn.address)+':', insn.mnemonic, insn.op_str)
    cnt+=1
    if cnt>200:break
