#Requires -Version 5.1
#Requires -RunAsAdministrator
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules\Carbon' -Resolve) `
                  -Function @('Install-CUser', 'Uninstall-CUser') `
                  -Verbose:$false

    $script:username = 'CarbonRevokePrivileg'
    $script:password = 'a1b2c3d4#'
    $script:credential =
        [pscredential]::New($script:username, (ConvertTo-SecureString -String $script:password -AsPlainText -Force))
    Install-CUser -Credential $script:credential -Description 'Account for testing Carbon Revoke-CPrivilege function.'
}

AfterAll {
    Uninstall-CUser -Username $script:username
}

Describe 'Revoke-CPrivilege' {
    BeforeEach {
        $privs = Get-CPrivilege -Identity $script:username | Where-Object { $_ -ne 'SeBatchLogonRight' }
        if ($privs)
        {
            Revoke-CPrivilege -Identity $script:username -Privilege $privs
        }

        Grant-CPrivilege -Identity $script:username -Privilege 'SeBatchLogonRight'
        (Test-CPrivilege -Identity $script:username -Privilege 'SeBatchLogonRight') | Should -BeTrue
        $Global:Error.Clear()
    }

    It 'revokes privilege for non existent principal' {
        Revoke-CPrivilege -Identity 'IDNOTEXIST' -Privilege SeBatchLogonRight -ErrorAction SilentlyContinue
        ($Global:Error.Count -gt 0) | Should -BeTrue
        ($Global:Error[0].Exception.Message -like '*Principal * not found*') | Should -BeTrue
    }

    It 'case insensitive' {
        Revoke-CPrivilege -Identity $script:username -Privilege SEBATCHLOGONRIGHT
        (Test-CPrivilege -Identity $script:username -Privilege SEBATCHLOGONRIGHT) | Should -BeFalse
        $Global:Error | Should -BeNullOrEmpty
    }

    It 'revokes non-existent privilege' {
        Revoke-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -BeFalse
        Revoke-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight
        $Global:Error | Should -BeNullOrEmpty
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -BeFalse
    }

    It 'validates privilege names' {
        Grant-CPrivilege -Identity $script:username -Privilege 'SeDebugPrivilege'
        Revoke-CPrivilege -Identity $script:username `
                          -Privilege 'SeDebugPrivilege', 'fubarsnafu', 'SeBatchLogonRight' `
                          -ErrorAction SilentlyContinue
        $Global:Error | Should -Match 'that privilege is unknown'
        Test-CPrivilege -Identity $script:username 'SeDebugPrivilege' | Should -BeFalse
        Test-CPrivilege -Identity $script:username 'fubarsnafu' | Should -BeFalse
        Test-CPrivilege -Identity $script:username 'SeTakeOwnershipPrivilege' | Should -BeFalse
    }

    It 'rejects all invalid privileges' {
        Revoke-CPrivilege -Identity $script:username -Privilege 'fubar', 'snafu' -ErrorAction SilentlyContinue
        $Global:Error | Should -Match 'those privileges are unknown'
        Test-CPrivilege -Identity $script:username 'SeBatchLogonRight' | Should -BeTrue
        Test-CPrivilege -Identity $script:username 'fubar' | Should -BeFalse
        Test-CPrivilege -Identity $script:username 'snafu' | Should -BeFalse
    }
}
