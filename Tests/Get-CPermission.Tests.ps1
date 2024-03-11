
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:user = 'CarbonTestUser1'
    $script:group1 = 'CarbonTestGroup1'
    $script:containerPath = $null
    $script:childPath = $null
}

Describe 'Get-CPermission' {
    BeforeEach {
        $script:containerPath = 'Carbon-Test-GetPermissions-{0}' -f ([IO.Path]::GetRandomFileName())
        $script:containerPath = Join-Path $env:Temp $script:containerPath

        New-Item -Path $script:containerPath -ItemType 'Directory' -Force
        Grant-CPermission -Path $script:containerPath -Identity $script:group1 -Permission Read

        $script:childPath = Join-Path $script:containerPath 'Child1'
        $null = New-Item $script:childPath -ItemType File
        Grant-CPermission -Path $script:childPath -Identity $script:user -Permission Read

        $Global:Error.Clear()
    }

    It 'should get permissions' {
        $perms = Get-CPermission -Path $script:childPath
        $perms | Should -Not -BeNullOrEmpty
        $group1Perms = $perms | Where-Object { $_.IdentityReference.Value -like "*\$script:group1" }
        $group1Perms | Should -BeNullOrEmpty

        $userPerms = $perms | Where-Object { $_.IdentityReference.Value -like "*\$script:user" }
        $userPerms | Should -Not -BeNullOrEmpty
        $userPerms | Should -BeOfType [Security.AccessControl.FileSystemAccessrule]
    }

    It 'should get inherited permissions' {
        $perms = Get-CPermission -Path $script:childPath -Inherited
        $perms | Should -Not -BeNullOrEmpty
        $group1Perms = $perms | Where-Object { $_.IdentityReference.Value -like "*\$script:group1" }
        $group1Perms | Should -Not -BeNullOrEmpty
        $group1Perms | Should -BeOfType [Security.AccessControl.FileSystemAccessrule]

        $userPerms = $perms | Where-Object { $_.IdentityReference.Value -like "*\$script:user" }
        $userPerms | Should -Not -BeNullOrEmpty
        $userPerms | Should -BeOfType [Security.AccessControl.FileSystemAccessRule]
    }

    It 'should get specific script:user permissions' {
        $perms = Get-CPermission -Path $script:childPath -Identity $script:group1
        $perms | Should -BeNullOrEmpty

        $perms = @( Get-CPermission -Path $script:childPath -Identity $script:user )
        $perms | Should -Not -BeNullOrEmpty
        $perms | Should -HaveCount 1
        $perms[0] | Should -Not -BeNullOrEmpty
        $perms[0] | Should -BeOfType [Security.AccessControl.FileSystemAccessrule]
    }

    It 'should get specific users inherited permissions' {
        $perms = Get-CPermission -Path $script:childPath -Identity $script:group1 -Inherited
        $perms | Should -Not -BeNullOrEmpty
        $perms | Should -BeOfType [Security.AccessControl.FileSystemAccessRule]
    }

    It 'should get permissions on registry key' {
        $perms = Get-CPermission -Path 'hkcu:\'
        $perms | Should -Not -BeNullOrEmpty
        $perms | Should -BeOfType [Security.AccessControl.RegistryAccessRule]
    }
}
