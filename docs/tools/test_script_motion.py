"""Build/run production motion-event helpers with mocked game memory on Windows.

Requires Visual Studio C++ tools. Example:
  python docs/tools/test_script_motion.py --msbuild <path-to-MSBuild.exe>
No game installation, LAN connection or dump/image.bin is required.
Generated build files remain under dump/tests/script_motion (gitignored).
"""
import argparse
from pathlib import Path
import subprocess
from xml.sax.saxutils import escape


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--msbuild', required=True, type=Path)
    parser.add_argument('--toolset', default='v145')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = root / 'dump/tests/script_motion'
    output.mkdir(parents=True, exist_ok=True)
    source = (root / 'source/Patch.cpp').read_text(encoding='utf-8')
    begin = source.index('struct ScriptMotionPulse')
    end = source.index('static volatile int g_brainTraceCh', begin)
    (output / 'script_motion_helpers.hpp').write_text(source[begin:end], encoding='utf-8')
    cases = escape(str(root / 'docs/tools/tests/script_motion_cases.cpp'), {'"': '&quot;'})
    project = output / 'script_motion_test.vcxproj'
    project.write_text(f'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>{escape(args.toolset)}</PlatformToolset><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(ProjectDir)bin\\</OutDir><IntDir>$(ProjectDir)obj\\</IntDir><TargetName>script_motion_test</TargetName></PropertyGroup>
<ItemDefinitionGroup><ClCompile><LanguageStandard>stdcpp20</LanguageStandard><ExceptionHandling>Sync</ExceptionHandling><AdditionalIncludeDirectories>$(ProjectDir);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><UndefinePreprocessorDefinitions>NDEBUG;%(UndefinePreprocessorDefinitions)</UndefinePreprocessorDefinitions></ClCompile><Link><SubSystem>Console</SubSystem></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="{cases}" /></ItemGroup>
<Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>''', encoding='utf-8')
    subprocess.run([str(args.msbuild), str(project), '-p:Configuration=Release',
                    '-p:Platform=x64', '-v:quiet', '-nologo'], check=True)
    subprocess.run([str(output / 'bin/script_motion_test.exe')], check=True)


if __name__ == '__main__':
    main()
