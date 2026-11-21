[CmdletBinding()]
param(
  [ValidateSet('all','dsh','codex','claude','cursor','copilot')]
  [string]$Agent = 'all',
  [ValidateSet('project','user')]
  [string]$Scope = 'project',
  [switch]$Force,
  [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$Name = 'system-design-primer'
$Source = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path -LiteralPath (Join-Path $Source 'SKILL.md') -PathType Leaf)) {
  throw "SKILL.md not found at package root: $Source"
}
$Base = (Get-Location).Path
if ($Scope -eq 'user') { $Base = $HOME }
$DshRoot = Join-Path $Base '.dsh'
if ($Scope -eq 'user') {
  if ([string]::IsNullOrWhiteSpace($env:DSH_HOME)) { $DshRoot = Join-Path $HOME '.dsh' }
  else { $DshRoot = $env:DSH_HOME }
}

$Parents = @()
switch ($Agent + ':' + $Scope) {
  'all:project' {
    $Parents += (Join-Path $Base '.dsh/skills')
    $Parents += (Join-Path $Base '.agents/skills')
    $Parents += (Join-Path $Base '.claude/skills')
    $Parents += (Join-Path $Base '.github/skills')
  }
  'all:user' {
    $Parents += (Join-Path $DshRoot 'skills')
    $Parents += (Join-Path $Base '.agents/skills')
    $Parents += (Join-Path $Base '.claude/skills')
    $Parents += (Join-Path $Base '.copilot/skills')
  }
  'dsh:project' { $Parents += (Join-Path $DshRoot 'skills') }
  'dsh:user' { $Parents += (Join-Path $DshRoot 'skills') }
  'codex:project' { $Parents += (Join-Path $Base '.agents/skills') }
  'codex:user' { $Parents += (Join-Path $Base '.agents/skills') }
  'claude:project' { $Parents += (Join-Path $Base '.claude/skills') }
  'claude:user' { $Parents += (Join-Path $Base '.claude/skills') }
  'cursor:project' { $Parents += (Join-Path $Base '.cursor/skills') }
  'cursor:user' { $Parents += (Join-Path $Base '.cursor/skills') }
  'copilot:project' { $Parents += (Join-Path $Base '.github/skills') }
  'copilot:user' { $Parents += (Join-Path $Base '.copilot/skills') }
}

$Items = @('SKILL.md','references','templates','evals','ATTRIBUTION.md','LICENSE','VERSION')
$ScriptItems = @('install.sh','install.ps1')
foreach ($Item in $Items) {
  if (-not (Test-Path -LiteralPath (Join-Path $Source $Item))) {
    throw "Required package entry is missing: $Item"
  }
}
foreach ($Item in $ScriptItems) {
  if (-not (Test-Path -LiteralPath (Join-Path $Source "scripts/$Item") -PathType Leaf)) {
    throw "Required script is missing: scripts/$Item"
  }
}

# Preflight every destination before changing any of them.
foreach ($Parent in $Parents) {
  $Destination = Join-Path $Parent $Name
  if ((Test-Path -LiteralPath $Destination) -and -not $Force) {
    throw "Target already exists: $Destination (use -Force to replace it)"
  }
}

foreach ($Parent in $Parents) {
  $Destination = Join-Path $Parent $Name
  if ($WhatIf) {
    Write-Host "Would install $Source -> $Destination"
    continue
  }

  New-Item -ItemType Directory -Force -Path $Parent | Out-Null
  $Staging = Join-Path $Parent (".$Name.tmp." + [guid]::NewGuid().ToString('N'))
  $Backup = $null
  try {
    New-Item -ItemType Directory -Path $Staging | Out-Null
    foreach ($Item in $Items) {
      Copy-Item -LiteralPath (Join-Path $Source $Item) -Destination $Staging -Recurse -Force
    }
    $ScriptsDestination = Join-Path $Staging "scripts"
    New-Item -ItemType Directory -Force -Path $ScriptsDestination | Out-Null
    foreach ($Item in $ScriptItems) {
      Copy-Item -LiteralPath (Join-Path $Source "scripts/$Item") -Destination $ScriptsDestination -Force
    }

    if (Test-Path -LiteralPath $Destination) {
      $Backup = Join-Path $Parent (".$Name.backup." + [guid]::NewGuid().ToString('N'))
      Move-Item -LiteralPath $Destination -Destination $Backup
    }

    try {
      Move-Item -LiteralPath $Staging -Destination $Destination
      $Staging = $null
    }
    catch {
      if ($Backup -and (Test-Path -LiteralPath $Backup) -and -not (Test-Path -LiteralPath $Destination)) {
        Move-Item -LiteralPath $Backup -Destination $Destination
        $Backup = $null
      }
      throw
    }

    if ($Backup -and (Test-Path -LiteralPath $Backup)) {
      Remove-Item -LiteralPath $Backup -Recurse -Force
      $Backup = $null
    }
    Write-Host "Installed: $Destination"
  }
  finally {
    if ($Staging -and (Test-Path -LiteralPath $Staging)) {
      Remove-Item -LiteralPath $Staging -Recurse -Force
    }
  }
}

if ($WhatIf) { Write-Host 'Dry run complete; no files changed.' }
else { Write-Host 'Installation complete. Reload the agent if the Skill is not discovered.' }
