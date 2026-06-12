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

    It 'builds admin association pattern lookup from policy map' {
        $lookup = ConvertTo-AdminPatternLookup -RawMap ([pscustomobject]@{
            'AdminUser1@example.com' = @('^Proj', '^Infra.*Corp')
        })

        $lookup.ContainsKey('adminuser1@example.com') | Should -Be $true
        @($lookup['adminuser1@example.com']).Count | Should -Be 2
        $lookup['adminuser1@example.com'][0] | Should -Be '^Proj'
    }

    It 'marks watched admin as associated when project matches policy pattern' {
        $watchedSet = @{ 'adminuser1@example.com' = $true }
        $assocLookup = @{ 'adminuser1@example.com' = @('^Proj') }

        $result = Resolve-WatchedAdminAssociation `
            -MailAddress 'AdminUser1@example.com' `
            -PrincipalName 'AdminUser1@example.com' `
            -WatchedExactSet $watchedSet `
            -AllowedProjectPatternsLookup $assocLookup `
            -ProjectName 'Proj-Platform'

        $result.IsWatchedAdmin | Should -Be $true
        $result.HasAssociationPolicy | Should -Be $true
        $result.IsAssociatedProjectForWatchedAdmin | Should -Be $true
        $result.IsUnexpectedWatchedAdmin | Should -Be $false
        $result.MatchedAssociationPattern | Should -Be '^Proj'
    }

    It 'marks watched admin as unexpected when project does not match policy pattern' {
        $watchedSet = @{ 'adminuser1@example.com' = $true }
        $assocLookup = @{ 'adminuser1@example.com' = @('^Admins') }

        $result = Resolve-WatchedAdminAssociation `
            -MailAddress 'AdminUser1@example.com' `
            -PrincipalName 'AdminUser1@example.com' `
            -WatchedExactSet $watchedSet `
            -AllowedProjectPatternsLookup $assocLookup `
            -ProjectName 'Proj-Platform'

        $result.IsWatchedAdmin | Should -Be $true
        $result.HasAssociationPolicy | Should -Be $true
        $result.IsAssociatedProjectForWatchedAdmin | Should -Be $false
        $result.IsUnexpectedWatchedAdmin | Should -Be $true
        $result.MatchedAssociationPattern | Should -Be $null
    }

    It 'does not mark watched admin as unexpected when no association policy exists' {
        $watchedSet = @{ 'adminuser1@example.com' = $true }
        $assocLookup = @{}

        $result = Resolve-WatchedAdminAssociation `
            -MailAddress 'AdminUser1@example.com' `
            -PrincipalName 'AdminUser1@example.com' `
            -WatchedExactSet $watchedSet `
            -AllowedProjectPatternsLookup $assocLookup `
            -ProjectName 'Proj-Platform'

        $result.IsWatchedAdmin | Should -Be $true
        $result.HasAssociationPolicy | Should -Be $false
        $result.IsAssociatedProjectForWatchedAdmin | Should -Be $false
        $result.IsUnexpectedWatchedAdmin | Should -Be $false
        $result.MatchedAssociationPattern | Should -Be $null
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
