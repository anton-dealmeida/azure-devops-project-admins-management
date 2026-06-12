# azure-devops-project-admins-management

Script-first toolkit to report and clean up Azure DevOps **Project Administrators** memberships with safe defaults.

## What it does

- Report which admins are in more than configured number of projects.
- Report which projects have more admins than configured minimum.
- Flag disallowed admins (exact list and/or regex patterns).
- Track watched admins (exact email list) and whether project membership matches association policy patterns.
- Flag dormant admins (based on last access age).
- Produce JSON + CSV + static HTML dashboard with:
    - admin -> project count/list
    - project -> admin count/list
- Remove dormant/disallowed/force-remove-all admins from Project Administrators with dry-run default.

## Files

- `config/policy.sample.json` - policy and guardrails.
- `scripts/Get-AdoProjectAdminReport.ps1` - read-only inventory and report export.
- `scripts/Invoke-AdoProjectAdminCleanup.ps1` - cleanup engine (dry-run unless `-Apply`).
- `scripts/AdoProjectAdminTools.ps1` - shared logic.
- `tests/AdoProjectAdminTools.Tests.ps1` - Pester safety tests for core planning logic.

## Requirements

- Azure CLI (`az`)
- Azure DevOps CLI extension (`azure-devops`)
- Permission to read/update project security groups in target organization

## Quick start

1. Copy policy template and edit values:

   ```powershell
   Copy-Item .\config\policy.sample.json .\config\policy.json
   ```

   Watched-admin association policy shape:

   ```json
   {
    "watchedExactEmails": [
      "AdminUser1@example.com"
    ],
    "allowedProjectPatternsByAdmin": {
      "AdminUser1@example.com": [
        "^Proj",
        "^Admins",
        "^Infra.*Corp"
      ]
    }
   }
   ```

   Notes:

   - `watchedExactEmails` uses exact email matching (case-insensitive after normalization).
   - `allowedProjectPatternsByAdmin` is object map: admin email -> regex patterns for allowed project names.
   - Report records include: `IsWatchedAdmin`, `HasAssociationPolicy`, `IsAssociatedProjectForWatchedAdmin`, `IsUnexpectedWatchedAdmin`, `MatchedAssociationPattern`.

2. Generate baseline report first (no changes):

   ```powershell
   .\scripts\Get-AdoProjectAdminReport.ps1 `
     -OrganizationUrl "https://dev.azure.com/<org>" `
     -PolicyPath ".\config\policy.json" `
     -OutputDirectory ".\reports"
   ```

3. Review:

    - `reports\project-admin-report.json`
    - `reports\project-admin-memberships.csv`
    - `reports\project-admin-report.html`

4. Run cleanup in dry-run mode:

```powershell
  .\scripts\Invoke-AdoProjectAdminCleanup.ps1 `
     -OrganizationUrl "https://dev.azure.com/<org>" `
     -PolicyPath ".\config\policy.json" `
     -ReportJsonPath ".\reports\project-admin-report.json" `
     -IncludeDisallowed `
     -IncludeDormant
```

5. Execute cleanup only after review:

```powershell
  .\scripts\Invoke-AdoProjectAdminCleanup.ps1 `
     -OrganizationUrl "https://dev.azure.com/<org>" `
     -PolicyPath ".\config\policy.json" `
     -ReportJsonPath ".\reports\project-admin-report.json" `
     -IncludeDisallowed `
     -IncludeDormant `
     -IncludeForceRemoveAll `
     -ExpectedSnapshotHash "<hash from report metadata>" `
     -Apply
```

   Notes:

    - `-Apply` now requires `-ReportJsonPath`.
    - report snapshot hash integrity is validated before removals.
    - stale report blocks apply by default (`-MaxReportAgeHours`, override with `-AllowStaleReport`).

## Safety behavior

- Dry-run default: no removals unless `-Apply`.
- Protected admins in policy are never removed.
- Minimum admins per project enforced by default.
- Optional `-BypassMinimumAdminsCheck` available for exceptional cases.
- Planned/executed cleanup logs are written to `reports\cleanup-logs`.
- Rollback script is generated for each apply run.

## Testing

Tests require **Pester v5+**. Install if needed:

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Force -Scope CurrentUser
Invoke-Pester .\tests\AdoProjectAdminTools.Tests.ps1
```