#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsTransientAdoError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $transientMarkers = @(
        '429',
        '503',
        '504',
        'temporarily unavailable',
        'timed out',
        'timeout',
        'connection reset',
        'connection aborted',
        'econnreset'
    )

    $normalized = $Message.ToLowerInvariant()
    foreach ($marker in $transientMarkers) {
        if ($normalized.Contains($marker)) {
            return $true
        }
    }

    return $false
}

function Get-JsonSnapshotHash {
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    $json = $Value | ConvertTo-Json -Depth 100 -Compress
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $hashBytes = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function ConvertTo-NormalizedAccountKey {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    return $Value.Trim().ToLowerInvariant()
}

function Invoke-AdoCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$AllowEmptyOutput,
        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 2
    )

    if ($RetryCount -lt 1) {
        $RetryCount = 1
    }

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        try {
            & az @Arguments 2>$null | Set-Content -LiteralPath $stdoutFile -Encoding UTF8
            $stdoutStr = Get-Content -LiteralPath $stdoutFile -Raw -Encoding UTF8
        }
        finally {
            Remove-Item -LiteralPath $stdoutFile -ErrorAction SilentlyContinue
        }

        if ($LASTEXITCODE -eq 0) {
            if ([string]::IsNullOrWhiteSpace($stdoutStr)) {
                if ($AllowEmptyOutput) {
                    return $null
                }

                throw "Azure CLI command returned empty output: az $($Arguments -join ' ')"
            }

            return ($stdoutStr | ConvertFrom-Json)
        }

        $flatArgs = ($Arguments -join ' ')
        $stderrCapture = (& az @Arguments 2>&1 | Out-String)
        $isTransient = Test-IsTransientAdoError -Message $stderrCapture
        $isLastAttempt = ($attempt -eq $RetryCount)
        if ($isLastAttempt -or -not $isTransient) {
            throw "Azure CLI command failed: az $flatArgs`n$stderrCapture"
        }

        Start-Sleep -Seconds ($RetryDelaySeconds * $attempt)
    }

    throw "Azure CLI command failed after retries: az $($Arguments -join ' ')"
}

function Get-AdoPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    if (-not (Test-Path -LiteralPath $PolicyPath)) {
        throw "Policy file not found: $PolicyPath"
    }

    $policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -Depth 100

    if ($null -eq $policy.minimumAdminsPerProject) {
        throw "Policy missing minimumAdminsPerProject."
    }

    if ($null -eq $policy.multiProjectThreshold) {
        $policy | Add-Member -MemberType NoteProperty -Name multiProjectThreshold -Value 1 -Force
    }

    if ($null -eq $policy.dormantDays) {
        $policy | Add-Member -MemberType NoteProperty -Name dormantDays -Value 90 -Force
    }

    if (-not $policy.skipMemberSubjectKinds) {
        $policy | Add-Member -MemberType NoteProperty -Name skipMemberSubjectKinds -Value @('group') -Force
    }

    if (-not $policy.disallowedPatterns) {
        $policy | Add-Member -MemberType NoteProperty -Name disallowedPatterns -Value @() -Force
    }

    if (-not $policy.disallowedExactEmails) {
        $policy | Add-Member -MemberType NoteProperty -Name disallowedExactEmails -Value @() -Force
    }

    if (-not $policy.protectedAdmins) {
        $policy | Add-Member -MemberType NoteProperty -Name protectedAdmins -Value @() -Force
    }

    if (-not $policy.forceRemoveAllAdmins) {
        $policy | Add-Member -MemberType NoteProperty -Name forceRemoveAllAdmins -Value @() -Force
    }

    return $policy
}

function Get-AdoProjects {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl,
        [string[]]$ProjectNames
    )

    $projectResponse = Invoke-AdoCliJson -Arguments @(
        'devops', 'project', 'list',
        '--org', $OrganizationUrl,
        '--output', 'json'
    )

    $projects = @($projectResponse.value)
    if ($ProjectNames -and $ProjectNames.Count -gt 0) {
        $nameSet = @{}
        foreach ($name in $ProjectNames) {
            $nameSet[(ConvertTo-NormalizedAccountKey -Value $name)] = $true
        }

        $projects = @(
            $projects | Where-Object {
                $nameSet.ContainsKey((ConvertTo-NormalizedAccountKey -Value $_.name))
            }
        )
    }

    return $projects
}

function Get-ProjectAdminGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl,
        [Parameter(Mandatory = $true)]
        [string]$ProjectName
    )

    $groups = @()
    $continuationToken = $null
    do {
        $args = @(
            'devops', 'security', 'group', 'list',
            '--org', $OrganizationUrl,
            '--project', $ProjectName,
            '--scope', 'project',
            '--output', 'json'
        )

        if ($continuationToken) {
            $args += @('--continuation-token', $continuationToken)
        }

        $response = Invoke-AdoCliJson -Arguments $args
        $groups += @($response.graphGroups)

        $continuationToken = $null
        if ($response.PSObject.Properties.Name -contains 'continuationToken') {
            $continuationToken = $response.continuationToken
        }
        elseif ($response.PSObject.Properties.Name -contains 'continuationtoken') {
            $continuationToken = $response.continuationtoken
        }
    } while ($continuationToken)

    if (-not $groups -or $groups.Count -eq 0) {
        throw "No security groups returned for project '$ProjectName'."
    }

    $adminGroup = @(
        $groups | Where-Object {
            $_.displayName -eq 'Project Administrators' -or
            $_.principalName -like '*\Project Administrators'
        }
    ) | Select-Object -First 1

    if (-not $adminGroup) {
        throw "Project Administrators group not found for project '$ProjectName'."
    }

    return $adminGroup
}

function Convert-MembershipResponseToMembers {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $MembershipResponse
    )

    if (-not $MembershipResponse) {
        return @()
    }

    if ($MembershipResponse -is [System.Array]) {
        return @($MembershipResponse)
    }

    if ($MembershipResponse.PSObject.Properties.Name -contains 'value') {
        return @($MembershipResponse.value)
    }

    if ($MembershipResponse.PSObject.Properties.Name -contains 'members') {
        $list = @()
        foreach ($memberProperty in $MembershipResponse.members.PSObject.Properties) {
            $member = $memberProperty.Value
            if ($member -and -not $member.descriptor) {
                $member | Add-Member -MemberType NoteProperty -Name descriptor -Value $memberProperty.Name -Force
            }

            if ($member) {
                $list += $member
            }
        }

        return $list
    }

    return @($MembershipResponse)
}

function Get-ProjectAdminMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl,
        [Parameter(Mandatory = $true)]
        [string]$GroupDescriptor
    )

    $membershipResponse = Invoke-AdoCliJson -Arguments @(
        'devops', 'security', 'group', 'membership', 'list',
        '--org', $OrganizationUrl,
        '--id', $GroupDescriptor,
        '--relationship', 'members',
        '--output', 'json'
    )

    return Convert-MembershipResponseToMembers -MembershipResponse $membershipResponse
}

function Get-AdoUserLookup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl
    )

    $lookup = @{}
    $top = 1000
    $skip = 0
    while ($true) {
        $response = Invoke-AdoCliJson -Arguments @(
            'devops', 'user', 'list',
            '--org', $OrganizationUrl,
            '--top', "$top",
            '--skip', "$skip",
            '--output', 'json'
        )

        $items = @($response.items)
        foreach ($user in $items) {
            $keys = @(
                (ConvertTo-NormalizedAccountKey -Value $user.mailAddress),
                (ConvertTo-NormalizedAccountKey -Value $user.principalName),
                (ConvertTo-NormalizedAccountKey -Value $user.user.principalName)
            ) | Where-Object { $_ }

            foreach ($key in $keys) {
                if (-not $lookup.ContainsKey($key)) {
                    $lookup[$key] = $user
                }
            }
        }

        if ($items.Count -lt $top) {
            break
        }

        $skip += $top
    }

    return $lookup
}

function Test-PatternMatch {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value,
        [string[]]$Patterns
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }

        if ($Value -match $pattern) {
            return $true
        }
    }

    return $false
}

function Get-AdoProjectAdminInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Policy
    )

    $projectNames = @($Policy.projectScope)
    $projects = Get-AdoProjects -OrganizationUrl $OrganizationUrl -ProjectNames $projectNames
    $userLookup = Get-AdoUserLookup -OrganizationUrl $OrganizationUrl

    $disallowedExactSet = @{}
    foreach ($entry in @($Policy.disallowedExactEmails)) {
        $key = ConvertTo-NormalizedAccountKey -Value $entry
        if ($key) { $disallowedExactSet[$key] = $true }
    }

    $protectedSet = @{}
    foreach ($entry in @($Policy.protectedAdmins)) {
        $key = ConvertTo-NormalizedAccountKey -Value $entry
        if ($key) { $protectedSet[$key] = $true }
    }

    $forceRemoveAllSet = @{}
    foreach ($entry in @($Policy.forceRemoveAllAdmins)) {
        $key = ConvertTo-NormalizedAccountKey -Value $entry
        if ($key) { $forceRemoveAllSet[$key] = $true }
    }

    $skipKinds = @($Policy.skipMemberSubjectKinds)
    $skipKindSet = @{}
    foreach ($kind in $skipKinds) {
        $key = ConvertTo-NormalizedAccountKey -Value $kind
        if ($key) { $skipKindSet[$key] = $true }
    }

    $records = @()
    foreach ($project in $projects) {
        $group = Get-ProjectAdminGroup -OrganizationUrl $OrganizationUrl -ProjectName $project.name
        $members = Get-ProjectAdminMembers -OrganizationUrl $OrganizationUrl -GroupDescriptor $group.descriptor

        foreach ($member in $members) {
            $subjectKind = ConvertTo-NormalizedAccountKey -Value $member.subjectKind
            if ($subjectKind -and $skipKindSet.ContainsKey($subjectKind)) {
                continue
            }

            $mailAddress = if ($member.mailAddress) { $member.mailAddress } elseif ($member.principalName -match '@') { $member.principalName } else { $null }
            $principalName = $member.principalName
            $displayName = if ($member.displayName) { $member.displayName } else { $member.principalName }

            $identityKey = @(
                (ConvertTo-NormalizedAccountKey -Value $mailAddress),
                (ConvertTo-NormalizedAccountKey -Value $principalName),
                (ConvertTo-NormalizedAccountKey -Value $displayName)
            ) | Where-Object { $_ } | Select-Object -First 1

            $userInfo = $null
            if ($identityKey -and $userLookup.ContainsKey($identityKey)) {
                $userInfo = $userLookup[$identityKey]
            }

            $lastAccessedDate = $null
            if ($userInfo -and $userInfo.lastAccessedDate) {
                $lastAccessedDate = [datetime]$userInfo.lastAccessedDate
            }

            $daysSinceLastAccess = $null
            if ($lastAccessedDate) {
                $daysSinceLastAccess = [math]::Floor(((Get-Date) - $lastAccessedDate).TotalDays)
            }

            $isDormant = $false
            if ($daysSinceLastAccess -ne $null -and $Policy.dormantDays -ne $null) {
                $isDormant = ($daysSinceLastAccess -ge [int]$Policy.dormantDays)
            }

            $candidateValues = @(
                (ConvertTo-NormalizedAccountKey -Value $mailAddress),
                (ConvertTo-NormalizedAccountKey -Value $principalName),
                (ConvertTo-NormalizedAccountKey -Value $displayName)
            ) | Where-Object { $_ }

            $isDisallowed = $false
            foreach ($candidate in $candidateValues) {
                if ($disallowedExactSet.ContainsKey($candidate)) {
                    $isDisallowed = $true
                    break
                }
            }

            if (-not $isDisallowed) {
                $isDisallowed = Test-PatternMatch -Value $mailAddress -Patterns @($Policy.disallowedPatterns)
            }

            if (-not $isDisallowed) {
                $isDisallowed = Test-PatternMatch -Value $principalName -Patterns @($Policy.disallowedPatterns)
            }

            $isProtected = $false
            foreach ($candidate in $candidateValues) {
                if ($protectedSet.ContainsKey($candidate)) {
                    $isProtected = $true
                    break
                }
            }

            $inForceRemoveAllList = $false
            foreach ($candidate in $candidateValues) {
                if ($forceRemoveAllSet.ContainsKey($candidate)) {
                    $inForceRemoveAllList = $true
                    break
                }
            }

            $records += [pscustomobject]@{
                ProjectId             = $project.id
                ProjectName           = $project.name
                GroupDescriptor       = $group.descriptor
                AdminDescriptor       = $member.descriptor
                AdminDisplayName      = $displayName
                AdminPrincipalName    = $principalName
                AdminMailAddress      = $mailAddress
                SubjectKind           = $member.subjectKind
                LastAccessedDate      = $lastAccessedDate
                DaysSinceLastAccess   = $daysSinceLastAccess
                IsDormant             = $isDormant
                IsDisallowed          = $isDisallowed
                IsProtected           = $isProtected
                InForceRemoveAllList  = $inForceRemoveAllList
            }
        }
    }

    $adminGroups = $records | Group-Object -Property {
        ConvertTo-NormalizedAccountKey -Value (
            if ($_.AdminMailAddress) { $_.AdminMailAddress } elseif ($_.AdminPrincipalName) { $_.AdminPrincipalName } else { $_.AdminDisplayName }
        )
    }

    $adminsInMoreThanOneProject = @(
        $adminGroups | Where-Object { $_.Count -gt [int]$Policy.multiProjectThreshold }
    )

    $projectGroups = $records | Group-Object -Property ProjectName
    $projectsAboveMinimum = @(
        $projectGroups | Where-Object { $_.Count -gt [int]$Policy.minimumAdminsPerProject }
    )

    $metadata = [pscustomobject]@{
        OrganizationUrl         = $OrganizationUrl
        GeneratedAtUtc          = (Get-Date).ToUniversalTime().ToString('o')
        MinimumAdminsPerProject = [int]$Policy.minimumAdminsPerProject
        MultiProjectThreshold   = [int]$Policy.multiProjectThreshold
        DormantDays             = [int]$Policy.dormantDays
    }

    $snapshotHash = Get-JsonSnapshotHash -Value ([pscustomobject]@{
        Metadata = $metadata
        Records  = $records
    })
    $metadata | Add-Member -MemberType NoteProperty -Name SnapshotHash -Value $snapshotHash -Force

    return [pscustomobject]@{
        Metadata = $metadata
        Records = $records
        Summary = [pscustomobject]@{
            TotalProjects                          = @($projectGroups).Count
            TotalProjectAdminMemberships           = @($records).Count
            DistinctAdmins                         = @($adminGroups).Count
            AdminsInMoreThanThresholdProjectsCount = @($adminsInMoreThanOneProject).Count
            ProjectsAboveMinimumAdminsCount        = @($projectsAboveMinimum).Count
            DisallowedMembershipsCount             = @($records | Where-Object { $_.IsDisallowed }).Count
            DormantMembershipsCount                = @($records | Where-Object { $_.IsDormant }).Count
            ForceRemoveAllMembershipsCount         = @($records | Where-Object { $_.InForceRemoveAllList }).Count
        }
    }
}

function New-AdoCleanupPlan {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Records,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Policy,
        [string[]]$ProjectNames,
        [switch]$IncludeDormant,
        [switch]$IncludeDisallowed,
        [switch]$IncludeForceRemoveAll,
        [switch]$BypassMinimumAdminsCheck
    )

    $workingRecords = @($Records)
    if ($ProjectNames -and $ProjectNames.Count -gt 0) {
        $projectSet = @{}
        foreach ($name in $ProjectNames) {
            $projectSet[(ConvertTo-NormalizedAccountKey -Value $name)] = $true
        }

        $workingRecords = @($workingRecords | Where-Object {
            $projectSet.ContainsKey((ConvertTo-NormalizedAccountKey -Value $_.ProjectName))
        })
    }

    $eligible = @($workingRecords | Where-Object {
        $candidate =
            ($IncludeDisallowed -and $_.IsDisallowed) -or
            ($IncludeDormant -and $_.IsDormant) -or
            ($IncludeForceRemoveAll -and $_.InForceRemoveAllList)

        $candidate -and -not $_.IsProtected
    })

    $projectCurrentCount = @{}
    foreach ($group in ($workingRecords | Group-Object ProjectName)) {
        $projectCurrentCount[$group.Name] = [int]$group.Count
    }

    $planned = @()
    foreach ($entry in $eligible) {
        $projectName = [string]$entry.ProjectName
        if (-not $projectCurrentCount.ContainsKey($projectName)) {
            continue
        }

        $currentCount = [int]$projectCurrentCount[$projectName]
        $wouldRemain = $currentCount - 1
        if ($wouldRemain -lt 0) {
            continue
        }

        if (-not $BypassMinimumAdminsCheck -and $wouldRemain -lt [int]$Policy.minimumAdminsPerProject) {
            continue
        }

        $reason = @()
        if ($entry.IsDisallowed) { $reason += 'disallowed' }
        if ($entry.IsDormant) { $reason += 'dormant' }
        if ($entry.InForceRemoveAllList) { $reason += 'force-remove-all' }

        $memberId = if ($entry.AdminDescriptor) {
            $entry.AdminDescriptor
        }
        elseif ($entry.AdminMailAddress) {
            $entry.AdminMailAddress
        }
        else {
            $entry.AdminPrincipalName
        }

        if ([string]::IsNullOrWhiteSpace($memberId)) {
            continue
        }

        $planned += [pscustomobject]@{
            ProjectName        = $projectName
            GroupDescriptor    = [string]$entry.GroupDescriptor
            MemberId           = [string]$memberId
            AdminDisplayName   = [string]$entry.AdminDisplayName
            AdminPrincipalName = [string]$entry.AdminPrincipalName
            AdminMailAddress   = [string]$entry.AdminMailAddress
            Reason             = ($reason -join ',')
        }

        $projectCurrentCount[$projectName] = $wouldRemain
    }

    return [pscustomobject]@{
        WorkingRecordsCount = $workingRecords.Count
        EligibleCount       = $eligible.Count
        Planned             = $planned
    }
}

function Convert-InventoryToHtml {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory
    )

    $summaryJson = ($Inventory.Summary | ConvertTo-Json -Depth 20 -Compress)
    $recordsJson = ($Inventory.Records | ConvertTo-Json -Depth 20 -Compress)
    $metadataJson = ($Inventory.Metadata | ConvertTo-Json -Depth 20 -Compress)

    return @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Azure DevOps Project Admin Report</title>
  <style>
    :root { color-scheme: light dark; --bg: #ffffff; --fg: #0f172a; --border: #e2e8f0; --muted: #64748b; --card: #ffffff; }
    @media (prefers-color-scheme: dark) { :root { --bg: #020817; --fg: #e2e8f0; --border: #1e293b; --muted: #94a3b8; --card: #0f172a; } }
    body { font-family: Inter, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; line-height: 1.4; background: var(--bg); color: var(--fg); }
    h1, h2 { margin: 0 0 10px 0; }
    .muted { color: var(--muted); }
    .cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin: 14px 0 20px; }
    .card { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--card); }
    .big { font-size: 1.4rem; font-weight: 600; }
    .controls { display: grid; grid-template-columns: 1fr auto auto; gap: 10px; margin: 0 0 16px; align-items: center; }
    input[type="search"] { border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; background: var(--card); color: var(--fg); }
    label { font-size: .9rem; color: var(--muted); display: flex; gap: 6px; align-items: center; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0 22px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    th, td { border-bottom: 1px solid var(--border); text-align: left; padding: 8px 6px; vertical-align: top; }
    th { font-size: 0.9rem; }
    .tag { border: 1px solid var(--border); border-radius: 999px; padding: 1px 8px; font-size: 0.78rem; margin-right: 4px; white-space: nowrap; }
    .danger { background: #dc2626; color: #fff; border-color: #dc2626; }
    .warn { background: #d97706; color: #fff; border-color: #d97706; }
    .ok { background: #16a34a; color: #fff; border-color: #16a34a; }
    .grid-two { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); }
    code { background: #64748b22; padding: 1px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Azure DevOps Project Admin Report</h1>
  <div class="muted" id="meta"></div>
  <div class="cards" id="summary"></div>
  <div class="controls">
    <input id="searchInput" type="search" placeholder="Search admin, email, project..." />
    <label><input id="onlyFlagged" type="checkbox" /> Only flagged</label>
    <label><input id="onlyAboveThreshold" type="checkbox" /> Only above threshold</label>
  </div>
  <div class="grid-two">
    <section>
      <h2>Admins by project count</h2>
      <table id="adminsTable">
        <thead><tr><th>Admin</th><th>Projects</th><th>Flags</th></tr></thead>
        <tbody></tbody>
      </table>
    </section>
    <section>
      <h2>Projects by admin count</h2>
      <table id="projectsTable">
        <thead><tr><th>Project</th><th>Admins</th><th>Flags</th></tr></thead>
        <tbody></tbody>
      </table>
    </section>
  </div>
  <section>
    <h2>Flagged memberships</h2>
    <table id="flaggedTable">
      <thead><tr><th>Project</th><th>Admin</th><th>Reason</th><th>Last access</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>
<script>
const summary = $summaryJson;
const records = $recordsJson;
const metadata = $metadataJson;

const adminKey = (r) => (r.AdminMailAddress || r.AdminPrincipalName || r.AdminDisplayName || '').toLowerCase();
const adminLabel = (r) => r.AdminMailAddress || r.AdminPrincipalName || r.AdminDisplayName || '(unknown)';
const escHtml = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

document.getElementById('meta').textContent =
  `Org: ${metadata.OrganizationUrl} | Generated: ${metadata.GeneratedAtUtc} | Min admins/project: ${metadata.MinimumAdminsPerProject} | Multi-project threshold: ${metadata.MultiProjectThreshold} | Dormant days: ${metadata.DormantDays}`;

const cardData = [
  ['Projects', summary.TotalProjects],
  ['Admin memberships', summary.TotalProjectAdminMemberships],
  ['Distinct admins', summary.DistinctAdmins],
  ['Admins above project threshold', summary.AdminsInMoreThanThresholdProjectsCount],
  ['Projects above min admins', summary.ProjectsAboveMinimumAdminsCount],
  ['Disallowed memberships', summary.DisallowedMembershipsCount],
  ['Dormant memberships', summary.DormantMembershipsCount],
  ['Force-remove-all matches', summary.ForceRemoveAllMembershipsCount],
];
document.getElementById('summary').innerHTML = cardData
  .map(([k,v]) => `<div class="card"><div class="muted">${k}</div><div class="big">${v}</div></div>`)
  .join('');

const admins = new Map();
for (const rec of records) {
  const key = adminKey(rec);
  if (!admins.has(key)) admins.set(key, { label: adminLabel(rec), projects: new Set(), flags: { disallowed: false, dormant: false, force: false } });
  const item = admins.get(key);
  item.projects.add(rec.ProjectName);
  item.flags.disallowed ||= !!rec.IsDisallowed;
  item.flags.dormant ||= !!rec.IsDormant;
  item.flags.force ||= !!rec.InForceRemoveAllList;
}

const adminRows = [...admins.values()]
  .map(v => ({ ...v, count: v.projects.size }))
  .sort((a,b) => b.count - a.count || a.label.localeCompare(b.label));

const mkFlag = (kind, text) => `<span class="tag ${kind}">${text}</span>`;
const projects = new Map();
for (const rec of records) {
  if (!projects.has(rec.ProjectName)) projects.set(rec.ProjectName, { name: rec.ProjectName, admins: new Set(), hasFlagged: false });
  const item = projects.get(rec.ProjectName);
  item.admins.add(adminKey(rec));
  item.hasFlagged ||= (!!rec.IsDisallowed || !!rec.IsDormant || !!rec.InForceRemoveAllList);
}
const projectRows = [...projects.values()]
  .map(v => ({ ...v, count: v.admins.size }))
  .sort((a,b) => b.count - a.count || a.name.localeCompare(b.name));

const flaggedRows = records
  .filter(r => r.IsDisallowed || r.IsDormant || r.InForceRemoveAllList)
  .sort((a,b) => (a.ProjectName || '').localeCompare(b.ProjectName || '') || adminLabel(a).localeCompare(adminLabel(b)));

function renderTables() {
  const q = (document.getElementById('searchInput').value || '').trim().toLowerCase();
  const onlyFlagged = document.getElementById('onlyFlagged').checked;
  const onlyAboveThreshold = document.getElementById('onlyAboveThreshold').checked;

  const adminFiltered = adminRows.filter(a => {
    const flagHit = a.flags.disallowed || a.flags.dormant || a.flags.force || a.count > metadata.MultiProjectThreshold;
    const thresholdHit = a.count > metadata.MultiProjectThreshold;
    const searchHit = !q || a.label.toLowerCase().includes(q);
    if (onlyFlagged && !flagHit) return false;
    if (onlyAboveThreshold && !thresholdHit) return false;
    return searchHit;
  });

  const adminTbody = document.querySelector('#adminsTable tbody');
  adminTbody.innerHTML = adminFiltered.map(a => {
    const flags = [
      a.count > metadata.MultiProjectThreshold ? mkFlag('warn', 'multi-project') : '',
      a.flags.disallowed ? mkFlag('danger', 'disallowed') : '',
      a.flags.dormant ? mkFlag('warn', 'dormant') : '',
      a.flags.force ? mkFlag('danger', 'force-remove-all') : ''
    ].join(' ');
    return `<tr><td><code>${escHtml(a.label)}</code></td><td>${a.count}</td><td>${flags}</td></tr>`;
  }).join('');

  const projectFiltered = projectRows.filter(p => {
    const thresholdHit = p.count > metadata.MinimumAdminsPerProject;
    const flagHit = p.hasFlagged || thresholdHit;
    const searchHit = !q || p.name.toLowerCase().includes(q);
    if (onlyFlagged && !flagHit) return false;
    if (onlyAboveThreshold && !thresholdHit) return false;
    return searchHit;
  });

  const projectTbody = document.querySelector('#projectsTable tbody');
  projectTbody.innerHTML = projectFiltered.map(p => {
    const flags = [
      p.count > metadata.MinimumAdminsPerProject ? mkFlag('warn', 'above-min') : mkFlag('ok', 'within-min'),
      p.hasFlagged ? mkFlag('danger', 'flagged-memberships') : ''
    ].join(' ');
    return `<tr><td>${escHtml(p.name)}</td><td>${p.count}</td><td>${flags}</td></tr>`;
  }).join('');

  const flaggedTbody = document.querySelector('#flaggedTable tbody');
  flaggedTbody.innerHTML = flaggedRows
    .filter(r => {
      const principal = adminLabel(r).toLowerCase();
      const project = (r.ProjectName || '').toLowerCase();
      if (!q) return true;
      return principal.includes(q) || project.includes(q);
    })
    .map(r => {
      const reasons = [
        r.IsDisallowed ? mkFlag('danger', 'disallowed') : '',
        r.IsDormant ? mkFlag('warn', 'dormant') : '',
        r.InForceRemoveAllList ? mkFlag('danger', 'force-remove-all') : '',
        r.IsProtected ? mkFlag('ok', 'protected') : ''
      ].join(' ');
      const last = r.LastAccessedDate ? `${escHtml(r.LastAccessedDate)} (${r.DaysSinceLastAccess ?? 'n/a'} days)` : 'n/a';
      return `<tr><td>${escHtml(r.ProjectName)}</td><td><code>${escHtml(adminLabel(r))}</code></td><td>${reasons}</td><td>${last}</td></tr>`;
    }).join('');
}

for (const id of ['searchInput','onlyFlagged','onlyAboveThreshold']) {
  document.getElementById(id).addEventListener('input', renderTables);
  document.getElementById(id).addEventListener('change', renderTables);
}
renderTables();
</script>
</body>
</html>
"@
}

function Export-AdoProjectAdminReport {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory,
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        [switch]$SkipHtml
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $jsonPath = Join-Path -Path $OutputDirectory -ChildPath 'project-admin-report.json'
    $csvPath = Join-Path -Path $OutputDirectory -ChildPath 'project-admin-memberships.csv'
    $htmlPath = Join-Path -Path $OutputDirectory -ChildPath 'project-admin-report.html'

    $Inventory | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $Inventory.Records | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    if (-not $SkipHtml) {
        $html = Convert-InventoryToHtml -Inventory $Inventory
        $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    }

    return [pscustomobject]@{
        JsonPath = $jsonPath
        CsvPath = $csvPath
        HtmlPath = if ($SkipHtml) { $null } else { $htmlPath }
    }
}
