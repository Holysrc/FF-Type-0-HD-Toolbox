# Decompile functions from the Ghidra project without opening the GUI.
#   .\decompile.ps1 out.c 0x140371A20 0x371140
# Project: C:\Tools\ghidra_projects\FFT0 (program fftype0hd.exe.unpacked.exe), created by
#   analyzeHeadless C:\Tools\ghidra_projects FFT0 -import dump\fftype0hd.exe.unpacked.exe
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Addresses
)
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
$ghidra = "C:\Tools\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat"
$scriptDir = $PSScriptRoot
$out = [IO.Path]::GetFullPath($OutFile)
& $ghidra "C:\Tools\ghidra_projects" FFT0 -process "fftype0hd.exe.unpacked.exe" -noanalysis `
    -scriptPath $scriptDir -postScript DecompileAt.java $out @Addresses 2>&1 |
    Select-String "DecompileAt|written|ERROR|Exception" | ForEach-Object { $_.Line }
