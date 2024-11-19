
#Requires -Version 5.1
#Requires -RunAsAdministrator
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules\Carbon' -Resolve) `
                  -Function @('Install-CService', 'Install-CUser', 'Uninstall-CUser', 'Uninstall-CService') `
                  -Verbose:$false

    $script:testDirPath = ''
    $script:testNum = 0
    $script:serviceName = 'CarbonGrantPrivilege'
    $script:username = 'CarbonGrantPrivilege'
    $script:password = 'a1b2c3d4#'
    $script:credential =
        [pscredential]::New($script:username, (ConvertTo-SecureString -String $script:password -AsPlainText -Force))
    Install-CUser -Credential $script:credential `
                    -Description 'Account for testing Carbon Grant-CPrivilege function.'
}

AfterAll {
    Uninstall-CUser -Username $script:username
}

Describe 'Grant-CPrivilege' {
    BeforeEach {
        $script:testDirPath = Join-Path -Path $TestDrive -ChildPath ($script:testNum++)
        New-Item -Path $script:testDirPath -ItemType 'Directory'
        Copy-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath 'NoOpService.exe' -Resolve) `
                  -Destination $script:testDirPath
        $servicePath = Join-Path -Path $script:testDirPath -ChildPath 'NoOpService.exe' -Resolve
        Install-CService -Name $script:serviceName -Path $servicePath -StartupType Manual -Credential $script:credential
        $privs = Get-CPrivilege -Identity $script:username
        if ($privs)
        {
            Revoke-CPrivilege -Identity $script:username -Privilege $privs
        }
        $Global:Error.Clear()
    }

    AfterEach {
        Uninstall-CService -Name $script:serviceName
    }

    It 'grants and revoke privileges' {
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -BeFalse
        (Get-CPrivilege -Identity $script:username | Where-Object { $_ -eq 'SeServiceLogonRight' }) |
            Should -BeNullOrEmpty

        Grant-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -BeTrue
        (Get-CPrivilege -Identity $script:username | Where-Object { $_ -eq 'SeServiceLogonRight' }) |
            Should -Not -BeNullOrEmpty

        Start-Service $serviceName

        Revoke-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight
        (Test-CPrivilege -Identity $script:username -Privilege SeServiceLogonRight) | Should -BeFalse
        (Get-CPrivilege -Identity $script:username | Where-Object { $_ -eq 'SeServiceLogonRight' }) |
            Should -BeNullOrEmpty

        Start-Service $serviceName -ErrorAction SilentlyContinue
        $Global:Error | Should -BeNullOrEmpty
    }

    It 'writes an error if principal not found' {
        Grant-CPrivilege -Identity 'IDNOTEXIST' -Privilege SeBatchLogonRight -ErrorAction SilentlyContinue
        ($Global:Error.Count -gt 0) | Should -BeTrue
        ($Global:Error[0].Exception.Message -like '*Principal * not found*') | Should -BeTrue
    }

    It 'treats privilege name case-insensitively' {
        Grant-CPrivilege -Identity $script:username -Privilege SESERVICELOGONRIGHT
        $Global:Error | Should -BeNullOrEmpty
        Test-CPrivilege -Identity $script:username -Privilege SESERVICELOGONRIGHT | Should -BeTrue
    }

    It 'validates privilege names' {
        Grant-CPrivilege -Identity $script:username `
                         -Privilege 'SeDebugPrivilege', 'fubarsnafu', 'SeTakeOwnershipPrivilege' `
                         -ErrorAction SilentlyContinue
        $Global:Error | Should -Match 'that privilege is unknown'
        Test-CPrivilege -Identity $script:username 'SeDebugPrivilege' | Should -BeTrue
        Test-CPrivilege -Identity $script:username 'fubarsnafu' | Should -BeFalse
        Test-CPrivilege -Identity $script:username 'SeTakeOwnershipPrivilege' | Should -BeTrue
    }

    It 'rejects all invalid privileges' {
        Grant-CPrivilege -Identity $script:username -Privilege 'fubar', 'snafu' -ErrorAction SilentlyContinue
        $Global:Error | Should -Match 'those privileges are unknown'
        Test-CPrivilege -Identity $script:username 'fubar' | Should -BeFalse
        Test-CPrivilege -Identity $script:username 'snafu' | Should -BeFalse
    }
}
