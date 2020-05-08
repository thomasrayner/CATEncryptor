#Requires -Modules Pester, Platyps

$moduleName = 'CATEncryptor'

$sw = [System.Diagnostics.Stopwatch]::new()
$sw.Start()
Push-Location $PSScriptRoot

Write-Output 'Building dotnet project and dependencies'
Push-Location '.\src'
dotnet build
Pop-Location

# Invoke-Pester -Path "$PSScriptRoot\tests\"

Write-Output 'Creating output directory "out"'
New-Item -Name 'out' -ItemType 'Directory' -ErrorAction 'SilentlyContinue'
New-Item -Name "out\$ModuleName" -ItemType 'Directory' -ErrorAction 'SilentlyContinue'

Write-Output 'Copying module manifest and dll to output directory'
Copy-Item -Path "$PSScriptRoot\$moduleName.ps*" -Destination ".\out\$ModuleName\" -Force
Copy-Item -Path "$PSScriptRoot\src\bin\Debug\netstandard2.0\$moduleName.dll" -Destination ".\out\$ModuleName\" -Force

# Write-Output 'Creating comment-based help xml'
# New-ExternalHelp '.\docs\' -OutputPath '.\out\en-US\' -Force

Pop-Location

$sw.Stop()
Write-Output "`n`nBuild complete`nElapsed time: $($sw.Elapsed)"
