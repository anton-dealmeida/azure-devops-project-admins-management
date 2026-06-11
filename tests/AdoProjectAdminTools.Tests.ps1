Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\scripts\AdoProjectAdminTools.ps1"

Describe 'AdoProjectAdminTools' {
    It 'normalizes account keys to lowercase and trim' {
        $result = ConvertTo-NormalizedAccountKey -Value '  User@Email.COM  '
        $result | Should -Be 'user@email.com'
    }

    It 'matches regex patterns for disallowed accounts' {
        $hit = Test-PatternMatch -Value 'svc-build@email.com' -Patterns @('^svc-.*@email\.com$')
        $hit | Should -Be $true
    }

    It 'keeps removals when bypass minimum admins check is enabled' {
        $policy = [pscustomobject]@{ minimumAdminsPerProject = 2 }
        $records = @(
            [pscustomobject]@{
                ProjectName='P1'; GroupDescriptor='g1'; AdminDescriptor='m1';
                AdminDisplayName='A1'; AdminPrincipalName='a1@email.com'; AdminMailAddress='a1@email.com';
                IsDisallowed=$true; IsDormant=$false; InForceRemoveAllList=$false; IsProtected=$false
            }
        )

        $plan = New-AdoCleanupPlan -Records $records -Policy $policy -IncludeDisallowed -BypassMinimumAdminsCheck
        @($plan.Planned).Count | Should -Be 1
    }

    It 'blocks protected admins from planned removals' {
        $policy = [pscustomobject]@{ minimumAdminsPerProject = 0 }
        $records = @(
            [pscustomobject]@{
                ProjectName='P1'; GroupDescriptor='g1'; AdminDescriptor='m1';
                AdminDisplayName='A1'; AdminPrincipalName='a1@email.com'; AdminMailAddress='a1@email.com';
                IsDisallowed=$true; IsDormant=$false; InForceRemoveAllList=$false; IsProtected=$true
            }
        )

        $plan = New-AdoCleanupPlan -Records $records -Policy $policy -IncludeDisallowed
        @($plan.Planned).Count | Should -Be 0
    }
}
