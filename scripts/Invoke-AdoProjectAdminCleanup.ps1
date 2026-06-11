#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OrganizationUrl,
    [Parameter(Mandatory = $false)]
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\config\policy.sample.json'),
    [Parameter(Mandatory = $false)]
    [string]$ReportJsonPath,
    [Parameter(Mandatory = $false)]
    [int]$MaxReportAgeHours = 24,
    [Parameter(Mandatory = $false)]
    [string[]]$ProjectNames,
    [switch]$IncludeDormant,
    [switch]$IncludeDisallowed,
    [switch]$IncludeForceRemoveAll,
    [switch]$Apply,
    [switch]$BypassMinimumAdminsCheck,
    [switch]$AllowStaleReport,
    [string]$ExpectedSnapshotHash,
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\reports\cleanup-logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdoProjectAdminTools.ps1')

if (-not $IncludeDormant -and -not $IncludeDisallowed -and -not $IncludeForceRemoveAll) {
    throw "Select at least one cleanup mode: -IncludeDormant, -IncludeDisallowed, -IncludeForceRemoveAll."
}

if ($Apply -and -not $ReportJsonPath) {
    throw "Apply mode requires -ReportJsonPath. Generate report first and apply from snapshot."
}

$resolvedPolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
$policy = Get-AdoPolicy -PolicyPath $resolvedPolicyPath

$inventory = $null
if ($ReportJsonPath) {
    $resolvedReportPath = (Resolve-Path -LiteralPath $ReportJsonPath).Path
    $inventory = Get-Content -LiteralPath $resolvedReportPath -Raw | ConvertFrom-Json -Depth 100

    if (-not $inventory.Metadata -or -not $inventory.Records) {
        throw "Invalid report JSON shape. Expected Metadata and Records."
    }

    if (-not $inventory.Metadata.SnapshotHash) {
        throw "Report snapshot missing Metadata.SnapshotHash. Re-generate report with latest script."
    }

    $metadataNoHash = [pscustomobject]@{
        OrganizationUrl         = $inventory.Metadata.OrganizationUrl
        GeneratedAtUtc          = $inventory.Metadata.GeneratedAtUtc
        MinimumAdminsPerProject = $inventory.Metadata.MinimumAdminsPerProject
        MultiProjectThreshold   = $inventory.Metadata.MultiProjectThreshold
        DormantDays             = $inventory.Metadata.DormantDays
    }
    $computedHash = Get-JsonSnapshotHash -Value ([pscustomobject]@{
        Metadata = $metadataNoHash
        Records  = $inventory.Records
    })

    if ($computedHash -ne [string]$inventory.Metadata.SnapshotHash) {
        throw "Report snapshot integrity check failed. Hash mismatch."
    }

    if ($ExpectedSnapshotHash) {
        $expected = ConvertTo-NormalizedAccountKey -Value $ExpectedSnapshotHash
        $actual = ConvertTo-NormalizedAccountKey -Value $inventory.Metadata.SnapshotHash
        if ($expected -ne $actual) {
            throw "Expected snapshot hash does not match report hash."
        }
    }

    $generatedAt = [datetime]$inventory.Metadata.GeneratedAtUtc
    $ageHours = ((Get-Date).ToUniversalTime() - $generatedAt.ToUniversalTime()).TotalHours
    if ($Apply -and -not $AllowStaleReport -and $ageHours -gt $MaxReportAgeHours) {
        throw "Report snapshot is stale (${ageHours:n1}h > $MaxReportAgeHours h). Re-run report or use -AllowStaleReport."
    }
}
else {
    $inventory = Get-AdoProjectAdminInventory -OrganizationUrl $OrganizationUrl -Policy $policy
}

$planResult = New-AdoCleanupPlan `
    -Records @($inventory.Records) `
    -Policy $policy `
    -ProjectNames $ProjectNames `
    -IncludeDormant:$IncludeDormant `
    -IncludeDisallowed:$IncludeDisallowed `
    -IncludeForceRemoveAll:$IncludeForceRemoveAll `
    -BypassMinimumAdminsCheck:$BypassMinimumAdminsCheck

if ($planResult.EligibleCount -eq 0) {
    Write-Host "No eligible memberships found for selected cleanup criteria."
    return
}

$planned = @($planResult.Planned)

if ($planned.Count -eq 0) {
    Write-Host "Cleanup candidates exist, but minimum-admin safety rule blocked all removals."
    return
}

Write-Host "Planned removals: $($planned.Count)"
$planned | Format-Table ProjectName, AdminPrincipalName, AdminMailAddress, Reason -AutoSize

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$plannedJsonPath = Join-Path -Path $OutputDirectory -ChildPath "planned-removals-$timestamp.json"
$plannedCsvPath = Join-Path -Path $OutputDirectory -ChildPath "planned-removals-$timestamp.csv"
$executedJsonPath = Join-Path -Path $OutputDirectory -ChildPath "executed-removals-$timestamp.json"
$rollbackScriptPath = Join-Path -Path $OutputDirectory -ChildPath "rollback-removals-$timestamp.ps1"

$planned | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $plannedJsonPath -Encoding UTF8
$planned | Export-Csv -LiteralPath $plannedCsvPath -NoTypeInformation -Encoding UTF8

if (-not $Apply) {
    Write-Host "Planned logs:"
    Write-Host "JSON: $plannedJsonPath"
    Write-Host "CSV : $plannedCsvPath"
    Write-Host "Dry run only. Add -Apply to execute removals."
    return $planned
}

$executed = @()
foreach ($item in $planned) {
    Invoke-AdoCliJson -AllowEmptyOutput -Arguments @(
        'devops', 'security', 'group', 'membership', 'remove',
        '--org', $OrganizationUrl,
        '--group-id', $item.GroupDescriptor,
        '--member-id', $item.MemberId,
        '--yes',
        '--output', 'json'
    ) | Out-Null

    Write-Host "Removed $($item.MemberId) from Project Administrators in $($item.ProjectName)."
    $executed += $item
}

$executed | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $executedJsonPath -Encoding UTF8
$rollbackLines = @(
    'Set-StrictMode -Version Latest',
    '$ErrorActionPreference = ''Stop''',
    '',
    '# Rollback generated by Invoke-AdoProjectAdminCleanup.ps1',
    '# Re-add removed memberships to project admin groups.',
    ''
)
foreach ($item in $executed) {
    $rollbackLines += "az devops security group membership add --org `"$OrganizationUrl`" --group-id `"$($item.GroupDescriptor)`" --member-id `"$($item.MemberId)`" --output json"
}
$rollbackLines -join "`r`n" | Set-Content -LiteralPath $rollbackScriptPath -Encoding UTF8

Write-Host "Planned logs:"
Write-Host "JSON: $plannedJsonPath"
Write-Host "CSV : $plannedCsvPath"
Write-Host "Executed log: $executedJsonPath"
Write-Host "Rollback script: $rollbackScriptPath"
Write-Host "Cleanup done."
return $executed
