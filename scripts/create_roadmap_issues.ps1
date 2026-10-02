<#
.SYNOPSIS
    Create the MERIDIAN roadmap on GitHub: labels, one milestone per phase, and one issue per item.

.DESCRIPTION
    Reads docs/roadmap/issues.json. Uses the GitHub CLI (gh), which must be installed and signed in
    (winget install --id GitHub.cli; gh auth login). Safe to run again: existing labels are updated, existing
    milestones are reused, and issues whose title already exists (open or closed) are skipped.

.EXAMPLE
    .\scripts\create_roadmap_issues.ps1 -Repo manabouprj/Meridian -DryRun
    .\scripts\create_roadmap_issues.ps1 -Repo manabouprj/Meridian
#>
param(
    [string]$Repo = "manabouprj/Meridian",
    [string]$File = (Join-Path $PSScriptRoot "..\docs\roadmap\issues.json"),
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI not found. Install it with: winget install --id GitHub.cli   then run: gh auth login"
}
gh auth status 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI is not signed in. Run: gh auth login" }

$roadmap = Get-Content -Raw -Encoding UTF8 $File | ConvertFrom-Json

function Invoke-Gh {
    param([string[]]$GhArgs)
    if ($DryRun) { Write-Host "[dry-run] gh $($GhArgs -join ' ')"; return $null }
    $out = & gh @GhArgs
    if ($LASTEXITCODE -ne 0) { throw "gh $($GhArgs -join ' ') failed" }
    return $out
}

# ---------------------------------------------------------------- labels
$labels = @(
    @{ name = "roadmap";     color = "5319e7"; description = "Planned work from the MERIDIAN roadmap" },
    @{ name = "infra";       color = "0e7490"; description = "Infrastructure, deployment, operations" },
    @{ name = "ingestion";   color = "1a7f37"; description = "Sources, mappers, retention" },
    @{ name = "detection";   color = "cf222e"; description = "Rules and correlations" },
    @{ name = "ai";          color = "8250df"; description = "Agents, evaluation, model governance" },
    @{ name = "integration"; color = "9a6700"; description = "LODESTAR, ITSM and other integrations" },
    @{ name = "ux";          color = "0969da"; description = "Analyst experience" },
    @{ name = "compliance";  color = "6e7781"; description = "Audit, regulatory and residency evidence" },
    @{ name = "security";    color = "b60205"; description = "Platform and supply-chain security" },
    @{ name = "repo";        color = "c5def5"; description = "Repository housekeeping" }
)
0..5 | ForEach-Object { $labels += @{ name = "phase-$_"; color = "ededed"; description = "Roadmap phase $_" } }
foreach ($l in $labels) {
    Invoke-Gh @("label", "create", $l.name, "--color", $l.color, "--description", $l.description, "--force", "--repo", $Repo) | Out-Null
}
Write-Host "Labels ready: $($labels.Count)"

# ---------------------------------------------------------------- milestones
$existingMilestones = @()
if (-not $DryRun) {
    $existingMilestones = (gh api "repos/$Repo/milestones?state=all&per_page=100" | ConvertFrom-Json) | ForEach-Object { $_.title }
}
foreach ($m in $roadmap.milestones) {
    if ($existingMilestones -contains $m) { Write-Host "Milestone exists: $m"; continue }
    Invoke-Gh @("api", "repos/$Repo/milestones", "-f", "title=$m") | Out-Null
    Write-Host "Milestone created: $m"
}

# ---------------------------------------------------------------- issues
$existingTitles = @()
if (-not $DryRun) {
    $existingTitles = (gh issue list --repo $Repo --state all --limit 1000 --json title | ConvertFrom-Json) | ForEach-Object { $_.title }
}
$created = 0; $skipped = 0
foreach ($i in $roadmap.issues) {
    if ($existingTitles -contains $i.title) { $skipped++; Write-Host "Exists, skipped: $($i.title)"; continue }
    $body = @(
        $i.description,
        "",
        "**Done when:** $($i.done_when)",
        "",
        "**Reference:** $($i.reference)",
        "",
        "_Created from docs/roadmap/issues.json._"
    ) -join "`n"
    $labelList = "roadmap,phase-$($i.phase),$($i.area)"
    Invoke-Gh @("issue", "create", "--repo", $Repo, "--title", $i.title, "--body", $body,
                "--label", $labelList, "--milestone", $i.milestone) | Out-Null
    $created++
    Write-Host "Issue created: $($i.title)"
}
Write-Host "Done: $created created, $skipped already existed."
