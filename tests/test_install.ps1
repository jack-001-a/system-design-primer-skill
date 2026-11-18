$ErrorActionPreference = 'Stop'
$ScriptPath = Join-Path $PSScriptRoot '..\scripts\install.ps1'
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("system-design-test-" + [guid]::NewGuid().ToString('N'))
$Project = Join-Path $TempRoot 'project'
$HomeDir = Join-Path $TempRoot 'home'
New-Item -ItemType Directory -Force -Path $Project, $HomeDir | Out-Null
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

  Set-Content -Path (Join-Path $Destination 'SKILL.md') -Value 'sentinel'
  & $ScriptPath -Agent codex -Scope project -Force
  if ((Get-Content (Join-Path $Destination 'SKILL.md') -Raw) -match 'sentinel') { throw 'Force did not replace old content' }
  & $ScriptPath -Agent all -Scope project -Force
  foreach ($Relative in @('.agents/skills/system-design-primer/SKILL.md','.claude/skills/system-design-primer/SKILL.md','.github/skills/system-design-primer/SKILL.md')) {
    if (-not (Test-Path (Join-Path $Project $Relative))) { throw "Missing project install: $Relative" }
  }
  Pop-Location
  Write-Host 'OK: PowerShell installer integration tests'
}
finally {
  while ((Get-Location).Path -eq $Project) { Pop-Location }
  Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
