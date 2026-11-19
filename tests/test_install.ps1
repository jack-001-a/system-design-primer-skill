$ErrorActionPreference = 'Stop'
$ScriptPath = Join-Path $PSScriptRoot '..\scripts\install.ps1'
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("system-design-test-" + [guid]::NewGuid().ToString('N'))
$Project = Join-Path $TempRoot 'project'
$HomeDir = Join-Path $TempRoot 'home'
$CustomDsh = Join-Path $TempRoot 'custom-dsh'
New-Item -ItemType Directory -Force -Path $Project, $HomeDir, $CustomDsh | Out-Null
$PreviousDshHome = $env:DSH_HOME
try {
  Push-Location $Project
  & $ScriptPath -Agent codex -Scope project -WhatIf
  if (Test-Path '.agents/skills/system-design-primer') { throw 'WhatIf created files' }

  & $ScriptPath -Agent codex -Scope project
  $Destination = '.agents/skills/system-design-primer'
  if (-not (Test-Path (Join-Path $Destination 'SKILL.md'))) { throw 'Skill entrypoint missing' }
  if (Test-Path (Join-Path $Destination '.git')) { throw '.git leaked into installed Skill' }

  $FailedAsExpected = $false
  try { & $ScriptPath -Agent codex -Scope project } catch { $FailedAsExpected = $true }
  if (-not $FailedAsExpected) { throw 'Existing-target guard did not reject overwrite' }
  & $ScriptPath -Agent dsh -Scope project
  if (-not (Test-Path '.dsh/skills/system-design-primer/SKILL.md')) { throw 'DSH project install missing' }

  Set-Content -Path (Join-Path $Destination 'SKILL.md') -Value 'sentinel'
  & $ScriptPath -Agent codex -Scope project -Force
  if ((Get-Content (Join-Path $Destination 'SKILL.md') -Raw) -match 'sentinel') { throw 'Force did not replace old content' }
  & $ScriptPath -Agent all -Scope project -Force
  foreach ($Relative in @('.dsh/skills/system-design-primer/SKILL.md','.agents/skills/system-design-primer/SKILL.md','.claude/skills/system-design-primer/SKILL.md','.github/skills/system-design-primer/SKILL.md')) {
    if (-not (Test-Path (Join-Path $Project $Relative))) { throw "Missing project install: $Relative" }
  }

  $env:DSH_HOME = $null
  & $ScriptPath -Agent dsh -Scope user
  if (-not (Test-Path (Join-Path $HOME '.dsh/skills/system-design-primer/SKILL.md'))) { throw 'Default user DSH install missing' }
  $env:DSH_HOME = $CustomDsh
  & $ScriptPath -Agent dsh -Scope user
  if (-not (Test-Path (Join-Path $CustomDsh 'skills/system-design-primer/SKILL.md'))) { throw 'Custom DSH_HOME install missing' }
  & $ScriptPath -Agent all -Scope user -Force
  foreach ($Relative in @('.agents/skills/system-design-primer/SKILL.md','.claude/skills/system-design-primer/SKILL.md','.copilot/skills/system-design-primer/SKILL.md')) {
    if (-not (Test-Path (Join-Path $HOME $Relative))) { throw "Missing user install: $Relative" }
  }
  Pop-Location
  Write-Host 'OK: PowerShell installer integration tests'
}
finally {
  $env:DSH_HOME = $PreviousDshHome
  while ((Get-Location).Path -eq $Project) { Pop-Location }
  Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
