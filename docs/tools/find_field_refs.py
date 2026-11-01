"""Find instructions in the dumped module that access [reg+DISP] for given displacements.
Usage: python docs/tools/find_field_refs.py 0x6b9 0xce4 [--base 0x7FF7ECD90000] [--dump path]
Walks .pdata RUNTIME_FUNCTION entries for function ranges and disassembles each with capstone.
Prints RVA of the instruction, the containing function start, and the instruction text."""
import struct, sys, os, capstone
args=[a for a in sys.argv[1:] if not a.startswith('--')]
opts={a.split('=')[0]:a.split('=',1)[1] for a in sys.argv[1:] if a.startswith('--') and '=' in a}
dump=opts.get('--dump') or os.environ.get('FFT0_DUMP') or os.path.join(os.path.dirname(__file__),'..','..','dump','image.bin')
data=open(dump,'rb').read()
pe=struct.unpack_from('<I',data,0x3c)[0]
nsec=struct.unpack_from('<H',data,pe+6)[0]; optsz=struct.unpack_from('<H',data,pe+20)[0]
secs={}
for i in range(nsec):
    o=pe+24+optsz+i*40; name=data[o:o+8].rstrip(b'\0').decode(); vs,va=struct.unpack_from('<II',data,o+8)
    secs[name]=(va,vs)
pva,psz=secs['.pdata']
disps=set(int(a,0) for a in args)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
hits=0
for o in range(pva,pva+psz,12):
    beg,end,unw=struct.unpack_from('<III',data,o)
    if beg==0 or end<=beg or end-beg>0x20000: continue
    for ins in md.disasm(data[beg:end],beg):
        for op in ins.operands:
            if op.type==capstone.x86.X86_OP_MEM and op.mem.disp in disps and op.mem.base not in (capstone.x86.X86_REG_RIP,capstone.x86.X86_REG_RSP,capstone.x86.X86_REG_RBP,0):
                print(f"{ins.address:06X} fn={beg:06X} disp={op.mem.disp:#x}  {ins.mnemonic} {ins.op_str}")
                hits+=1
print("hits:",hits)
