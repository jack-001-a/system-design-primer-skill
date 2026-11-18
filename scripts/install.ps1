param(
  [ValidateSet('all','codex','claude','cursor','copilot')]
  [string]$Agent = 'all',
  [ValidateSet('project','user')]
  [string]$Scope = 'project',
  [switch]$Force,
  [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$Source = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path (Join-Path $Source 'SKILL.md'))) {
  throw 'Cannot find SKILL.md next to scripts/.'
}

$Base = (Get-Location).Path
if ($Scope -eq 'user') { $Base = $HOME }

$Parents = @()
switch ($Agent) {
  'all' {
    $Parents += (Join-Path $Base '.agents/skills')
    $Parents += (Join-Path $Base '.claude/skills')
  }
  'codex'   { $Parents += (Join-Path $Base '.agents/skills') }
  'claude'  { $Parents += (Join-Path $Base '.claude/skills') }
  'cursor'  { $Parents += (Join-Path $Base '.cursor/skills') }
  'copilot' { $Parents += (Join-Path $Base '.github/skills') }
}

$Name = 'system-design-primer'
foreach ($Parent in $Parents) {
  $Destination = Join-Path $Parent $Name
  if ((Test-Path $Destination) -and -not $Force) {
    throw "Target exists; not overwriting: $Destination. Re-run with -Force to replace it."
  }
  if ($WhatIf) {
    Write-Host "Would install: $Source -> $Destination"
    continue
  }
  New-Item -ItemType Directory -Force -Path $Parent | Out-Null
  if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
  Copy-Item -Recurse -Force $Source $Destination
  Write-Host "Installed: $Destination"
}
if ($WhatIf) { Write-Host 'Dry run complete; no files changed.' }
else { Write-Host 'Done. Refresh/restart the agent if the skill is not discovered.' }
