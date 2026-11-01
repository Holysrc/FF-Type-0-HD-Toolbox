"""Smoke-test the real launcher with a harmless fake game in a path with spaces."""
import argparse
from pathlib import Path
import shutil
import subprocess
import time
from xml.sax.saxutils import escape

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--msbuild', required=True)
args = parser.parse_args()
out = root / 'dump/tests/launcher smoke'
(out / 'WIN').mkdir(parents=True, exist_ok=True)
fake = out / 'fake.cpp'
fake.write_text(r'''
#include <windows.h>
#include <fstream>
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR args, int) {
    wchar_t cwd[MAX_PATH]; GetCurrentDirectoryW(MAX_PATH, cwd);
    std::wofstream log(L"child.txt"); log << args << L"\n" << cwd << L"\n"; log.close();
    Sleep(350); return 37;
}
''')
project = out / 'fake.vcxproj'
project.write_text(f'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v145</PlatformToolset></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)WIN\\</OutDir><IntDir>$(ProjectDir)obj\\</IntDir><TargetName>fftype0hd</TargetName></PropertyGroup>
<ItemDefinitionGroup><ClCompile><RuntimeLibrary>MultiThreaded</RuntimeLibrary><ExceptionHandling>Sync</ExceptionHandling></ClCompile><Link><SubSystem>Windows</SubSystem></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="{escape(str(fake))}" /></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" /></Project>''')
subprocess.run([args.msbuild, str(project), '-p:Configuration=Release', '-p:Platform=x64', '-v:quiet', '-nologo'], check=True)
launcher = out / 'fftype0hdlauncher.exe'
shutil.copy2(root / 'build/nolauncher/fftype0hdlauncher.exe', launcher)
shutil.copy2(out / 'WIN/fftype0hd.exe', out / 'fftype0hdlauncher.exe.orig')
ini = out / 'WIN/FFT0HD Unlocker.ini'
for setting, arguments, directory, expected in [
    (1, [], out / 'WIN', '0'),
    (1, ['--marker', 'hello world'], out / 'WIN', '0 --marker "hello world"'),
    (0, ['--marker', 'launcher settings'], out, '--marker "launcher settings"'),
]:
    ini.write_text(f'[Intro]\nSkipLauncher={setting}\n')
    before = time.monotonic()
    result = subprocess.run([str(launcher), *arguments], cwd=root, timeout=10)
    assert result.returncode == 37, result.returncode
    assert time.monotonic() - before >= 0.3, 'Launcher failed to wait for the child'
    received = (directory / 'child.txt').read_text().splitlines()
    assert received == [expected, str(directory)], received
    assert 'game exited with code 37 (0x25)' in (directory / 'nolauncher.log').read_text()
    print(f'PASS: SkipLauncher={setting}, args={arguments}, correct working directory, child wait and exit code')
print('PASS: launcher smoke checks (Shift key and real Steam/game remain manual checks)')
