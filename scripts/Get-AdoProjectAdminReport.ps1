#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OrganizationUrl,
    [Parameter(Mandatory = $false)]
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\config\policy.sample.json'),
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\reports'),
    [switch]$SkipHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AdoProjectAdminTools.ps1')

$resolvedPolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
$policy = Get-AdoPolicy -PolicyPath $resolvedPolicyPath

$inventory = Get-AdoProjectAdminInventory -OrganizationUrl $OrganizationUrl -Policy $policy
$paths = Export-AdoProjectAdminReport -Inventory $inventory -OutputDirectory $OutputDirectory -SkipHtml:$SkipHtml

Write-Host "Report generated."
Write-Host "JSON: $($paths.JsonPath)"
Write-Host "CSV : $($paths.CsvPath)"
if ($paths.HtmlPath) {
    Write-Host "HTML: $($paths.HtmlPath)"
}
if ($inventory.Metadata.SnapshotHash) {
    Write-Host "SnapshotHash: $($inventory.Metadata.SnapshotHash)"
}

Write-Output $inventory
