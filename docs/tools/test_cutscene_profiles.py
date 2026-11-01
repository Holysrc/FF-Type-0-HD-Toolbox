"""Expanded production-helper checks; invoked by test_judecca_cutscenes.py."""
import ctypes
import itertools
import json
from pathlib import Path
import re
import struct
from audit_cutscene_gates import atels, OUT, ROOT
from build_cutscene_profiles import collect, render, CLIPS

def run(lib):
    assert (ROOT/'source/include/CutscenePartyProfiles.h').read_text()==render()
    profiles,guards=collect()
    lib.scene_hash.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    lib.scene_hash.restype=ctypes.c_uint64
    lib.scene_eligible.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_float,ctypes.c_int,ctypes.c_int,ctypes.c_int]
    lib.scene_missing.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_uint]
    entries=json.loads((OUT/'manifest.json').read_text())
    modules={}
    for entry in entries:
        for _,code,pool,_ in atels((OUT/entry['cache']).read_bytes()):
            h=lib.scene_hash(code,len(code));modules.setdefault(h,(code,pool))
    for i,(scene,pc,size,pool,h,inside) in enumerate(guards):
        code,actual_pool=modules[h]
        assert len(code)==size and pool==actual_pool
        for alive in (-1,0,1,2,3,4,1.5,float('nan')):
            assert bool(lib.scene_eligible(i,pc,alive,scene,scene,6))==(alive in (1,2))
        assert not lib.scene_eligible(i,pc+2,1,scene,scene,6)
        if inside:
            for stage in range(14):
                assert bool(lib.scene_eligible(i,pc,1,scene,scene,stage))==(5<=stage<=8)
            assert not lib.scene_eligible(i,pc,1,0,scene,6)
            assert not lib.scene_eligible(i,pc,1,scene,7855,6)
        # A changed command, header, name table or constant pool must fail the
        # complete-module check, even when command PC and comparison agree.
        for offset in (0,pc-6,pc,pool,size-1):
            damaged=bytearray(code);damaged[offset]^=1
            assert lib.scene_hash(bytes(damaged),size)!=h
        assert lib.scene_hash(code[:-1],size-1)!=h
    # Both real mission captures still pass the stronger whole-module check.
    for name,pc in [('native30_run_20260919_192921/FFT0HD Unlocker.ini_stream_21B4550F9E0.bin',0x64E),
                    ('compare_working_20260919_201240/FFT0HD Unlocker.ini_script_0.bin',0x203A)]:
        data=(ROOT/'dump/judecca_intro'/name).read_bytes()[512:]
        assert any(gpc==pc and len(data)>=n and lib.scene_hash(data[:n],n)==h
                   for _,gpc,n,_,h,inside in guards if not inside)
    # Full-game inventory: no global spoof of CMD5F. In particular cut7855's
    # native count3/2/1 alternatives are excluded, as are non-cinematic checks.
    checks=json.loads((OUT/'party_count_checks.json').read_text())
    matched=0
    by_id={e['id']:e for e in entries}
    for c in checks:
        e=by_id[c['file_id']]
        _,code,_,_=next(m for m in atels((OUT/e['cache']).read_bytes()) if m[0]==c['module'])
        hits=[g for g in guards if g[1]==c['pc'] and g[4]==lib.scene_hash(code,len(code))]
        if '7855' in c['file']: assert not hits
        matched+=bool(hits)
    assert 33<=matched<len(checks)
    for scene,_,_,_,clips in profiles:
        assert tuple(lib.scene_clip(scene,i) for i in range(len(clips)))==clips
        assert lib.scene_clip(scene,len(clips))==-1
        for empty,slot,stage,channel in itertools.product(range(8),range(3),(3,4,5,8,11,12),(-2,-1,0,1,2,6,66)):
            expected=4<=stage<=11 and (channel==-1 or (channel==slot and empty&(1<<slot)))
            assert bool(lib.scene_missing(channel,f'PC_{slot}'.encode(),scene,scene,stage,empty))==bool(expected)
        for name in (None,b'',b'PC_',b'PC_3',b'PC_10',b'EVE_PC_0',b'PC_ACTOR',b'0001'):
            assert not lib.scene_missing(-1,name,scene,scene,6,7)
        assert not lib.scene_missing(-1,b'PC_1',scene,7855,6,7)
        assert not lib.scene_missing(-1,b'PC_1',7855,scene,6,7)

    # Independently decode each native scene's actual PC motion commands,
    # tracking CMD219 default targets used by nested play-motion expressions.
    source=(ROOT/'docs/tools/scriptdis.py').read_text()
    source=source[source.index('OPS ='):source.index('start = int(sys.argv[2])')]
    for scene,expected in CLIPS.items():
        e=next(e for e in entries if Path(e['name']).stem==f'cut{scene}')
        _,code,pool,names=next(atels((OUT/e['cache']).read_bytes()))
        count=struct.unpack_from('<H',code,names)[0];name_map={}
        for i in range(count):
            _,idx,offset,n=struct.unpack_from('<HHHH',code,names+i*8)
            start=names+count*8+offset;name_map[idx]=code[start:start+n].rstrip(b'\0')
        scope={'struct':struct,'code':code,'const':lambda i:struct.unpack_from('<f',code,pool+i*4)[0],'cmdindex':lambda _:0}
        exec(source,scope);header=40;found=set()
        while header<names:
            _,length=struct.unpack_from('<II',code,header);pc=header+8;end=pc+length;default=None
            while pc<end:
                nxt,text=scope['stmt'](pc)
                target=re.search(r' -> id(\d+)$',text)
                if text.startswith('CMD219['):
                    assert target;default=int(target[1])
                if 'CMD3[' in text:
                    actor=int(target[1]) if target else default
                    assert actor is not None, (scene,hex(pc),'unknown motion target')
                    if name_map[actor] in (b'PC_0',b'PC_1',b'PC_2'):
                        clip=re.search(r'CMD3\[0\]\(\((\d+)\)',text)
                        assert clip,(scene,hex(pc),'dynamic PC clip')
                        found.add(int(clip[1]))
                pc=nxt
            header=(end+3)&~3
        assert found==set(expected),(scene,found,expected)
    print(f'Expanded profiles: {len(profiles)} scenes/{len(guards)} guards; {matched}/{len(checks)} cached CMD5F occurrences recognized')
    print('Full-module corruption, zero/full-party, unsupported scene, placeholder, captured-byte and PC-clip coverage checks passed')
