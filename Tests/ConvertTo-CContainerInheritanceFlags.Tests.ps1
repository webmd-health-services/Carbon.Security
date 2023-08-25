
using module '..\Carbon.Permissions'

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:username = 'CarbonTestUser'
}


Describe 'ConvertTo-CContainerInheritanceFlag' {
    It 'should convert to ntfs container inheritance flags' {
        $tempDir = 'Carbon+{0}+{1}' -f ((Split-Path -Leaf -Path $PSCommandPath),([IO.Path]::GetRandomFileName()))
        $tempDir = Join-Path -Path $env:TEMP -ChildPath $tempDir
        New-Item -Path $tempDir -ItemType 'Directory' | Out-Null

        try
        {
            foreach ($flag in [Enum]::GetValues([Carbon_Permissions_ContainerInheritanceFlags]))
            {
                Grant-CPermission -Path $tempDir -Identity $script:username -Permission FullControl -ApplyTo $flag
                $perm = Get-CPermission -Path $tempDir -Identity $script:username
                InModuleScope 'Carbon.Permissions' {
                    param(
                        $perm
                    )

                    ConvertTo-CContainerInheritanceFlag -InheritanceFlags $perm.InheritanceFlags `
                                                        -PropagationFlags $perm.PropagationFlags
                } -Parameters @{ perm = $perm ; } |
                    Should -Be $flag
            }
        }
        finally
        {
            if( Test-Path $tempDir )
            {
                Remove-Item $tempDir -Recurse -Force
            }
        }
    }

    It 'should convert to registry container inheritance flags' {
        $tempDir = 'Carbon+{0}+{1}' -f ((Split-Path -Leaf -Path $PSCommandPath),([IO.Path]::GetRandomFileName()))
        $tempDir = Join-Path -Path 'hkcu:\' -ChildPath $tempDir
        New-Item -Path $tempDir

        try
        {
            foreach ($flag in [Enum]::GetValues([Carbon_Permissions_ContainerInheritanceFlags]))
            {
                Grant-CPermission -Path $tempDir -Identity $script:username -Permission ReadKey -ApplyTo $flag
                $perm = Get-CPermission -Path $tempDir -Identity $script:username
                InModuleScope 'Carbon.Permissions' {
                    param(
                        $perm
                    )

                    ConvertTo-CContainerInheritanceFlag -InheritanceFlags $perm.InheritanceFlags `
                                                        -PropagationFlags $perm.PropagationFlags
                } -Parameters @{ perm = $perm } |
                    Should -Be $flag
            }
        }
        finally
        {
            Remove-Item $tempDir
        }
    }

}
