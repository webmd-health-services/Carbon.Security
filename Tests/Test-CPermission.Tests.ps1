
using namespace System.Security.AccessControl

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $psModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesPath -ChildPath 'Carbon.Registry' -Resolve) `
                  -Function @('Install-CRegistryKey') `
                  -Global `
                  -Verbose:$false

    $script:identity = 'CarbonTestUser'
    $script:tempDir = Join-Path -Path $env:TEMP -ChildPath "Carbon-Test-CPermission-$([IO.Path]::GetRandomFileName())"
    New-Item (Join-Path -path $script:tempDir -ChildPath 'File') -ItemType File -Force

    $script:dirPath = Join-Path -Path $script:tempDir -ChildPath 'Directory'
    $script:filePath = Join-Path -Path $script:dirPath -ChildPath 'File'
    New-Item -Path $script:filePath -ItemType File -Force -ErrorAction Ignore
    Grant-CPermission -Identity $script:identity `
                      -Permission ReadAndExecute `
                      -Path $script:dirPath `
                      -ApplyTo LeavesOnly

    $script:tempKeyPath = 'hkcu:\Software\Carbon\Test'
    $script:keyPath = Join-Path -Path $script:tempKeyPath -ChildPath 'Test-CPermission'
    Install-CRegistryKey -Path $script:keyPath
    $script:childKeyPath = Join-Path -Path $script:keyPath -ChildPath 'ChildKey'
    Grant-CPermission -Identity $script:identity `
                      -Permission 'ReadKey','WriteKey' `
                      -Path $script:keyPath `
                      -ApplyTo LeavesOnly

    $script:testDirPermArgs = @{
        Path = $script:dirPath;
        Identity = $script:identity;
    }

    $script:testFilePermArgs = @{
        Path = $script:filePath;
        Identity = $script:identity;
    }
}

AfterAll {
    Remove-Item -Path $script:tempDir -Recurse -ErrorAction Ignore
    Remove-Item -Path $script:tempKeyPath -Recurse -ErrorAction Ignore
}

Describe 'Test-CPermission' {
    BeforeEach {
        $Global:Error.Clear()
    }

    It 'should handle non existent path' {
        Test-CPermission -Path 'C:\I\Do\Not\Exist' -Identity $script:identity -Permission 'FullControl' -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
        $Global:Error | Should -HaveCount 1
        $Global:Error | Should -Match 'path does not exist'
    }

    It 'should check ungranted permission on file system' {
        Test-CPermission @testDirPermArgs -Permission 'Write' | Should -BeFalse
    }

    It 'should check granted permission on file system' {
        Test-CPermission @testDirPermArgs -Permission 'Read' | Should -BeTrue
    }

    It 'should check strict partial permission on file system' {
        Test-CPermission @testDirPermArgs -Permission 'Read' -Strict | Should -BeFalse
    }

    It 'should check strict permission on file system' {
        Test-CPermission @testDirPermArgs -Permission 'ReadAndExecute' -Strict | Should -BeTrue
    }

    It 'should exclude inherited permission' {
        Test-CPermission @testFilePermArgs -Permission 'ReadAndExecute' | Should -BeFalse
    }

    It 'should include inherited permission' {
        Test-CPermission @testFilePermArgs -Permission 'ReadAndExecute' -Inherited | Should -BeTrue
    }

    It 'should exclude inherited partial permission' {
        Test-CPermission @testFilePermArgs -Permission 'ReadAndExecute' -Strict | Should -BeFalse
    }

    It 'should include inherited strict permission' {
        Test-CPermission @testFilePermArgs -Permission 'ReadAndExecute' -Inherited -Strict | Should -BeTrue
    }

    It 'should ignore applies to flags on file' {
        $warning = @()
        Test-CPermission @testFilePermArgs `
                         -Permission 'ReadAndExecute' `
                         -ApplyTo ContainerSubcontainersAndLeaves `
                         -OnlyApplyToChildren `
                         -Inherited `
                         -WarningVariable 'warning' `
                         -WarningAction SilentlyContinue |
            Should -BeTrue
        $warning | Should -Not -BeNullOrEmpty
        $warning[0] | Should -Match 'test "applies to" flags on path.*because it is a file'
    }

    It 'should check ungranted permission on registry' {
        Test-CPermission -Path $script:keyPath -Identity $script:identity -Permission 'Delete' | Should -BeFalse
    }

    It 'should check granted permission on registry' {
        Test-CPermission -Path $script:keyPath -Identity $script:identity -Permission 'ReadKey' | Should -BeTrue
    }

    It 'should check strict partial permission on registry' {
        Test-CPermission -Path $script:keyPath -Identity $script:identity -Permission 'ReadKey' -Strict | Should -BeFalse
    }

    It 'should check strict permission on registry' {
        Test-CPermission -Path $script:keyPath -Identity $script:identity -Permission 'ReadKey','WriteKey' -Strict |
            Should -BeTrue
    }

    It 'checks applies to flags' {
        Test-CPermission @testDirPermArgs -Permission 'ReadAndExecute' -ApplyTo ContainerSubcontainersAndLeaves |
            Should -BeFalse
        Test-CPermission @testDirPermArgs -Permission 'ReadAndExecute' -ApplyTo LeavesOnly | Should -BeTrue
        Test-CPermission @testDirPermArgs -Permission 'ReadAndExecute' -ApplyTo LeavesOnly -OnlyApplyToChildren |
            Should -BeFalse
    }
}
