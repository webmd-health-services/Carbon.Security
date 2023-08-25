
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)
}

Describe 'ConvertTo-CProviderAccessControlRights' {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Permissions' -Resolve)
    InModuleScope 'Carbon.Permissions' {
        It 'should convert file system value' {
            (ConvertTo-CProviderAccessControlRights -ProviderName 'FileSystem' -InputObject 'Read') | Should -Be ([Security.AccessControl.FileSystemRights]::Read)
        }

        It 'should convert file system values' {
            $expected = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
            $actual = ConvertTo-CProviderAccessControlRights -ProviderName 'FileSystem' -InputObject 'Read','Write'
            $actual | Should -Be $expected
        }

        It 'should convert file system value from pipeline' {
            $expected = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
            $actual = 'Read','Write' | ConvertTo-CProviderAccessControlRights -ProviderName 'FileSystem'
            $actual | Should -Be $expected
        }

        It 'should convert registry value' {
            $expected = [Security.AccessControl.RegistryRights]::Delete
            $actual = 'Delete' | ConvertTo-CProviderAccessControlRights -ProviderName 'Registry'
            $actual | Should -Be $expected
        }

        It 'should handle invalid right name' {
            $Global:Error.Clear()
            (ConvertTo-CProviderAccessControlRights -ProviderName 'FileSystem' -InputObject 'BlahBlah','Read' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
            $Global:Error.Count | Should -Be 1
        }
    }
}
