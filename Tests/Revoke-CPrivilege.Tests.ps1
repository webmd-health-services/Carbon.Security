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
        Grant-CPrivilege -Identity $script:username -Privilege 'SeBatchLogonRight'
        (Test-CPrivilege -Identity $script:username -Privilege 'SeBatchLogonRight') | Should -Be $true
        $Global:Error.Clear()
    }

    It 'revokes privilege for non existent user' {
        Revoke-CPrivilege -Identity 'IDNOTEXIST' -Privilege SeBatchLogonRight -ErrorAction SilentlyContinue
        ($Global:Error.Count -gt 0) | Should -Be $true
        ($Global:Error[0].Exception.Message -like '*Identity * not found*') | Should -Be $true
    }

    It 'case sensitive' {
        Revoke-CPrivilege -Identity $script:username -Privilege SEBATCHLOGONRIGHT
        (Test-CPrivilege -Identity $script:username -Privilege SEBATCHLOGONRIGHT) | Should -Be $false
        (Test-CPrivilege -Identity $script:username -Privilege SeBatchLogonRight) | Should -Be $false
    }

    It 'revoke non existent privilege' {
        $Global:Error.Clear()
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -Be $false
        Revoke-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight
        $Global:Error.Count | Should -Be 0
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -Be $false
    }

}
