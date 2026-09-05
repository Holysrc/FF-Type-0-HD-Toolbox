import struct, sys
import os as _os
# dump path: $FFT0_DUMP, else ../../dump/image.bin next to this repo, else ./image.bin
_IMGP = _os.environ.get("FFT0_DUMP") or (_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin") if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "dump", "image.bin")) else "image.bin")
IMG = open(_IMGP, "rb").read()
BASE = 0x140000000
TEXT_START, TEXT_END = 0x1000, 0x5A0000

def find_callers(target_rva):
    out = []
    for o in range(TEXT_START, TEXT_END - 5):
        if IMG[o] == 0xE8:
            rel = struct.unpack_from("<i", IMG, o + 1)[0]
            if o + 5 + rel == target_rva:
                out.append(o)
        elif IMG[o] == 0xE9:
            rel = struct.unpack_from("<i", IMG, o + 1)[0]
            if o + 5 + rel == target_rva:
                out.append(o)
    return out

if __name__ == "__main__":
    for a in sys.argv[1:]:
        t = int(a, 16) - BASE
        print(f"--- callers of {a} ---")
        for o in find_callers(t):
            kind = "call" if IMG[o] == 0xE8 else "jmp"
            print(f"  {hex(BASE + o)}: {kind}")
