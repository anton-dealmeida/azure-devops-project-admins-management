# Copilot instructions for azure-devops-project-admins-management

## Build, test, lint commands

- No dedicated build/lint pipeline in repo.
- Run unit tests with PowerShell + Pester:
  - Full test file: `Invoke-Pester .\tests\AdoProjectAdminTools.Tests.ps1`
  - Single test case: `Invoke-Pester .\tests\AdoProjectAdminTools.Tests.ps1 -TestName 'marks watched admin as associated when project matches policy pattern'`
- Generate inventory/report:
  - `.\scripts\Get-AdoProjectAdminReport.ps1 -OrganizationUrl "https://dev.azure.com/<org>" -PolicyPath ".\config\policy.json" -OutputDirectory ".\reports"`
- Dry-run cleanup plan:
  - `.\scripts\Invoke-AdoProjectAdminCleanup.ps1 -OrganizationUrl "https://dev.azure.com/<org>" -PolicyPath ".\config\policy.json" -ReportJsonPath ".\reports\project-admin-report.json" -IncludeDisallowed -IncludeDormant`

## High-level architecture

- Entry points:
  - `scripts/Get-AdoProjectAdminReport.ps1` (read-only report export)
  - `scripts/Invoke-AdoProjectAdminCleanup.ps1` (plan/apply removals)
- Shared engine:
  - `scripts/AdoProjectAdminTools.ps1` contains policy parsing, Azure DevOps CLI wrappers, inventory collection, cleanup planning, report export, HTML rendering.
- Data flow:
  1. `Get-AdoPolicy` loads/normalizes policy defaults.
  2. `Get-AdoProjectAdminInventory` enumerates projects, resolves Project Administrators memberships, computes flags (disallowed/dormant/protected/force-remove-all/watched-association).
  3. `Export-AdoProjectAdminReport` writes JSON/CSV/HTML.
  4. Cleanup script loads report snapshot and validates integrity via `Metadata.SnapshotHash` before apply.
  5. `New-AdoCleanupPlan` enforces minimum-admin safety unless `-BypassMinimumAdminsCheck`.

## Key conventions

- Keep all identity comparisons normalized through `ConvertTo-NormalizedAccountKey` (trim + lowercase).
- Keep policy shape stable; add defaults in `Get-AdoPolicy` when introducing new fields.
- `watchedExactEmails` is exact-email list only; `allowedProjectPatternsByAdmin` is object map: admin email -> regex project-name patterns.
- Report records are compatibility-sensitive; add new fields without removing existing fields consumed by cleanup/report views.
- Apply mode is snapshot-driven: never bypass `-ReportJsonPath` + hash validation behavior.

## Session-friction guardrails (from this repo history)

- Branch naming guardrail: never infer branch names from chat mode/skill names. Before PR actions, confirm actual branch with `git --no-pager branch --show-current`.
- Pester version guardrail: tests use Pester v5 assertion style (`Should -Be`). Before judging failures, detect Pester major version and install/import v5 when needed.
- Agent-merge automation guardrail: for repeated agent-merge tick prompts, run merge-status check once per tick and execute only currently authorized actions; if authorization set unchanged, return concise no-op status.
- Baseline-first policy edits: for policy/schema requests, fetch `origin/main` and inspect current config/docs before implementing to keep schema naming/shape aligned.
