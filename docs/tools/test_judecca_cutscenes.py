"""Compile the production eligibility helpers and test against captured script bytes.

Requires the two local diagnostic captures and VS2026 MSBuild; no game process.
"""
import ctypes
from pathlib import Path
import struct
import subprocess
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'dump/tests/judecca_cutscenes'
OUT.mkdir(parents=True, exist_ok=True)
HEADER = ROOT / 'source/include/JudeccaCutsceneGate.h'
(OUT / 'test.cpp').write_text('''
#include "JudeccaCutsceneGate.h"
#include "CutscenePartyProfiles.h"
extern "C" __declspec(dllexport) unsigned long long scene_hash(const unsigned char* p, size_t n) {
    return CutscenePartyProfiles::Fingerprint(p,n);
}
extern "C" __declspec(dllexport) int scene_eligible(unsigned i, unsigned pc, float alive, int prepared, int current, int stage) {
    return CutscenePartyProfiles::Eligible(CutscenePartyProfiles::guards[i],pc,alive,prepared,current,stage);
}
extern "C" __declspec(dllexport) int scene_missing(int channel, const char* name, int armed, int current, int stage, unsigned empty) {
    return CutscenePartyProfiles::MissingActor(channel,name,armed,current,stage,empty);
}
extern "C" __declspec(dllexport) int scene_clip(int scene, int index) {
    const auto* p = CutscenePartyProfiles::Find(scene);
    return !p || index < 0 || static_cast<unsigned>(index) >= p->clipCount ? -1 : p->clips[index];
}
extern "C" __declspec(dllexport) int match(unsigned pc, const unsigned char* p,
    size_t n, float threshold, float scene, float secondary) {
    return JudeccaCutsceneGate::Match(pc, p, n, threshold, scene, secondary);
}
extern "C" __declspec(dllexport) int allowed(float alive, const int* models) {
    return JudeccaCutsceneGate::CanOverride(alive, models);
}
extern "C" __declspec(dllexport) int skip_missing(int channel, const char* name,
    int armed, int current, int stage, unsigned emptySlots) {
    return JudeccaCutsceneGate::SkipMissingActor(channel, name, armed, current, stage, emptySlots);
}
extern "C" __declspec(dllexport) int choose(const int* models) {
    return JudeccaCutsceneGate::ChooseStandIn(models);
}
extern "C" __declspec(dllexport) int resource(int model) { return JudeccaCutsceneGate::standInResources[model]; }
extern "C" __declspec(dllexport) int bank(int model) { return JudeccaCutsceneGate::standInBanks[model]; }
extern "C" __declspec(dllexport) int clip_count() { return sizeof(JudeccaCutsceneGate::standInClips) / sizeof(int); }
extern "C" __declspec(dllexport) int clip(int index) { return JudeccaCutsceneGate::standInClips[index]; }
extern "C" __declspec(dllexport) int cast_scope(int armed, int current, int stage) {
    return JudeccaCutsceneGate::StandInScope(armed, current, stage);
}
''', encoding='utf-8')
(OUT / 'test.vcxproj').write_text(f'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><ProjectGuid>{{EAD97564-0E19-4BFA-8343-C05678F55A11}}</ProjectGuid></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>DynamicLibrary</ConfigurationType><PlatformToolset>v145</PlatformToolset></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)bin\\</OutDir><IntDir>$(ProjectDir)obj\\</IntDir><TargetName>gate_test</TargetName></PropertyGroup>
<ItemDefinitionGroup><ClCompile><AdditionalIncludeDirectories>{escape(str(HEADER.parent))}</AdditionalIncludeDirectories><LanguageStandard>stdcpp17</LanguageStandard><RuntimeLibrary>MultiThreaded</RuntimeLibrary></ClCompile></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="test.cpp" /></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" /></Project>''', encoding='utf-8')
msbuild = r'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe'
with (OUT / 'build.log').open('w') as log:
    subprocess.run([msbuild, str(OUT / 'test.vcxproj'), '/p:Configuration=Release',
                    '/p:Platform=x64', '/v:minimal', '/nologo'], stdout=log, stderr=log, check=True)
lib = ctypes.CDLL(str(OUT / 'bin/gate_test.dll'))
lib.match.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t,
                      ctypes.c_float, ctypes.c_float, ctypes.c_float]
lib.match.restype = ctypes.c_int
lib.allowed.argtypes = [ctypes.c_float, ctypes.POINTER(ctypes.c_int)]
lib.allowed.restype = ctypes.c_int
lib.skip_missing.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
lib.skip_missing.restype = ctypes.c_int

cases = [
    ('native30_run_20260919_192921/FFT0HD Unlocker.ini_stream_21B4550F9E0.bin', 0x64E, 30, 65, 7555),
    ('compare_working_20260919_201240/FFT0HD Unlocker.ini_script_0.bin', 0x203A, 50, 425, 7553),
]
for name, pc, size, index, scene in cases:
    blob = (ROOT / 'dump/judecca_intro' / name).read_bytes()
    code = blob[512:]
    pool = struct.unpack_from('<Q', blob, 0x150)[0] - struct.unpack_from('<Q', blob, 0x118)[0]
    threshold, secondary, actual = [struct.unpack_from('<f', code, pool + i * 4)[0] for i in (2, 1, index)]
    window = code[pc - 12:pc - 12 + size]
    assert lib.match(pc, window, size, threshold, actual, secondary) == scene
    for offset in range(size):
        damaged = bytearray(window)
        damaged[offset] ^= 1
        assert lib.match(pc, bytes(damaged), size, threshold, actual, secondary) == 0
    for bad_pc in (0, pc - 1, pc + 1, 0xFFFFFFFF):
        assert lib.match(bad_pc, window, size, threshold, actual, secondary) == 0
    for bad in (0.0, 1.0, 3.0, float('nan')):
        assert lib.match(pc, window, size, bad, actual, secondary) == 0
    assert lib.match(pc, window, size - 1, threshold, actual, secondary) == 0
    assert lib.match(pc, None, size, threshold, actual, secondary) == 0
    assert lib.match(pc, window, size, threshold, actual + 1, secondary) == 0
    if scene == 7553:
        assert lib.match(pc, window, size, threshold, actual, 1.0) == 0
    print(f'scene{scene}: captured bytes match; all byte mutations, wrong PC/constants/size rejected')

models = (ctypes.c_int * 3)(10, 11, 6)
for alive in (-1, 0, 1, 2, 3, 4, 1.5, float('nan')):
    assert bool(lib.allowed(alive, models)) == (alive in (1, 2))
for invalid in ((10, -2, 6), (10, 14, 6), (10, 10, 6), (10, 11, 11), (-1, -1, -1)):
    assert lib.allowed(1, (ctypes.c_int * 3)(*invalid)) == 0
for party, alive, expected in (((10, -1, 9), 1, True), ((10, -1, 9), 2, True),
                               ((10, -1, -1), 1, True), ((-1, 10, -1), 1, True),
                               ((-1, -1, 10), 1, True), ((10, -1, -1), 2, False)):
    arg = (ctypes.c_int * 3)(*party)
    assert bool(lib.allowed(alive, arg)) == expected
    assert tuple(arg) == party
assert lib.allowed(1, None) == 0
assert list(models) == [10, 11, 6]
for scene in (7553, 7555):
    for stage in range(0, 14):
        for name in (b'PC_0', b'PC_1', b'PC_2'):
            assert bool(lib.skip_missing(-1, name, scene, scene, stage, 0)) == (4 <= stage <= 11)
    for channel in (-2, 0, 1, 2, 65, 66):
        assert not lib.skip_missing(channel, b'PC_1', scene, scene, 6, 0)
    for name in (None, b'', b'PC', b'PC_', b'PC_3', b'PC_10', b'this', b'0001', b'pc_1'):
        assert not lib.skip_missing(-1, name, scene, scene, 6, 7)
    for other in (0, 7554, 7553 if scene == 7555 else 7555):
        assert not lib.skip_missing(-1, b'PC_1', scene, other, 6, 7)
        assert not lib.skip_missing(-1, b'PC_1', other, scene, 6, 7)
    for empty in range(8):
        for slot in range(3):
            name = f'PC_{slot}'.encode()
            for channel in (-2, -1, 0, 1, 2, 3, 7, 65, 66):
                for stage in (0, 3, 4, 5, 6, 8, 9, 10, 11, 12):
                    expected = 4 <= stage <= 11 and (channel == -1 or
                        (channel == slot and bool(empty & (1 << slot))))
                    assert bool(lib.skip_missing(channel, name, scene, scene, stage, empty)) == expected

# Regression: the "empty" PC_1 is a real actor pointer/channel, not a failed name lookup.
capture = ROOT / 'dump/judecca_intro/partial_party_v2_run_20260919_210132'
actor = (capture / 'FFT0HD Unlocker.ini_scene_000_actor_ch1.bin').read_bytes()
assert struct.unpack_from('<h', actor, 0x360)[0] == -1
assert struct.unpack_from('<h', actor, 0x2B8)[0] == -1
assert struct.unpack_from('<II', actor, 0x934) == (0, 0)
assert lib.skip_missing(1, b'PC_1', 7555, 7555, 6, 2)
assert not lib.skip_missing(0, b'PC_0', 7555, 7555, 6, 2)
assert not lib.skip_missing(2, b'PC_2', 7555, 7555, 6, 2)
print('Captured placeholder ch1 regression and all empty-slot masks/name/channel/stage combinations passed')
print('Missing slot from failed test accepted; missing-name fallback restricted to armed scene/PC names')
image = (ROOT / 'dump/image.bin').read_bytes()
sig = bytes.fromhex('66 0F 6E 05 1C 84 2F 00 0F 5B C0 F3 0F 11 41 30 C3')
assert image.count(sig) == 1 and image[0x35F520:0x35F520 + len(sig)] == sig
ptr = struct.unpack_from('<Q', image, 0x612368 + 0x5E * 0x30)[0]
assert ptr - 0x7FF7ECD90000 == 0x35F520
resolver_sig = bytes.fromhex('40 53 48 83 EC 30 48 8B 05 93 72 28 00 48 33 C4')
assert image.count(resolver_sig) == 1 and image[0x383E60:0x383E60 + len(resolver_sig)] == resolver_sig
for rva in (0x3708D4, 0x370D58, 0x370E80):
    assert image[rva] == 0xE8 and rva + 5 + struct.unpack_from('<i', image, rva + 1)[0] == 0x383E60
print('Native model/count guards and original handler signature/registry verified; all checks passed')

# Compare production casting data to the independently decoded native helper.
import itertools
import re
decoded = (ROOT / 'dump/cutscene_audit/cut7558-decoded.txt').read_text()
native_cast = {int(m): (int(bank), int(resource)) for m, bank, resource in re.findall(
    r'CASE \((\d+)\):\n\w+: CMD27C\[0\]\(\((\d+)\).*?EXPR3 \(v1\[0\] (\d+) =\)', decoded, re.S)}
for model in range(12):
    assert (lib.bank(model), lib.resource(model)) == native_cast[model]
lib.choose.argtypes = [ctypes.POINTER(ctypes.c_int)]
assert lib.choose(None) == -1
for party in itertools.product(range(-1, 14), repeat=3):
    if -1 not in party or len([m for m in party if m >= 0]) != len(set(m for m in party if m >= 0)):
        continue
    values = (ctypes.c_int * 3)(*party)
    for slot, model in enumerate(party):
        if model == -1:
            chosen = lib.choose(values)
            assert 0 <= chosen < 12 and chosen not in values
            values[slot] = chosen
    assert len(set(values)) == 3
for armed, scene, stage in itertools.product((0, 7553, 7555, 7558), (0, 7553, 7555, 7558), range(14)):
    assert bool(lib.cast_scope(armed, scene, stage)) == (armed == scene == 7555 and 5 <= stage <= 8)
for rva, dest in ((0x34C6B1, 0x34B880), (0x34B5A1, 0x384960)):
    assert image[rva] == 0xE8 and rva + 5 + struct.unpack_from('<i', image, rva + 1)[0] == dest
for opcode, dest in ((0x25B, 0x366340), (0xEE, 0x363EB0), (0x27B, 0x366CB0), (0x20, 0x35D500), (0x2, 0x35C600)):
    assert struct.unpack_from('<Q', image, 0x612368 + opcode * 0x30)[0] - 0x7FF7ECD90000 == dest
print('Stand-in resource/bank mapping matches native script; unique casting, scope, lifecycle calls and command registry passed')
scene = (ROOT / 'dump/judecca_intro/scene7555-decoded.txt').read_text()
# The only CMD3 target outside PC_0/1/2 is the boss's2598 loop. PC helpers
# contain weapon visibility commands, no additional play-motion commands.
scene_pc_clips = {int(n) for n in re.findall(r'CMD3\[0\]\(\((\d+)\)', scene)} - {2598}
production_clips = [lib.clip(i) for i in range(lib.clip_count())]
assert len(production_clips) == len(set(production_clips))
assert set(production_clips) == scene_pc_clips == {7, 67, 68, 69, 71, 2400}
print('Stand-in preload list covers every PC animation in captured cut7555, including closing; no boss clips')

from test_cutscene_profiles import run as run_profiles
run_profiles(lib)
