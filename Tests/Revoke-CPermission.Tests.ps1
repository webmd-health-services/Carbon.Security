
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $psModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesPath -ChildPath 'Carbon.Cryptography' -Resolve) `
                  -Function ('Install-CCertificate', 'Uninstall-CCertificate') `
                  -Global `
                  -Verbose:$false

    $script:testDirPath = ''
    $script:testNum = 0
    $script:username = 'CarbonGrantPerms'
    $containerPath = $null
    $privateKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\CarbonTestPrivateKey.pfx' -Resolve
}

Describe 'Revoke-CPermission' {
    BeforeEach {
        $Global:Error.Clear()
        $script:testDirPath = Join-Path -Path $TestDrive -ChildPath $script:testNum
        New-Item -Path $script:testDirPath -ItemType 'Directory'
        Grant-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl'
    }

    AfterEach {
        $script:testNum += 1
    }

    It 'when user has multiple access control entries on an item' {
        Grant-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'Read'
        $perm = Get-CPermission -Path $script:testDirPath -Identity $script:username
        Mock -CommandName 'Get-CPermission' -ModuleName 'Carbon.Permissions' -MockWith { $perm ; $perm }.GetNewClosure()
        $Global:Error.Clear()
        Revoke-CPermission -Path $script:testDirPath -Identity $script:username
        $Global:Error | Should -BeNullOrEmpty
        Carbon.Permissions\Get-CPermission -Path $script:testDirPath -Identity $script:username | Should -BeNullOrEmpty
    }

    It 'should revoke permission' {
        Revoke-CPermission -Path $script:testDirPath -Identity $script:username
        $Global:Error.Count | Should -Be 0
        (Test-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl') | Should -BeFalse
    }

    It 'should not revoke inherited permissions' {
        Get-CPermission -Path $script:testDirPath -Inherited |
            Where-Object { $_.IdentityReference -notlike ('*{0}*' -f $script:username) } |
            ForEach-Object {
                $result = Revoke-CPermission -Path $script:testDirPath -Identity $_.IdentityReference
                $Global:Error.Count | Should -Be 0
                $result | Should -BeNullOrEmpty
                (Test-CPermission -Identity $_.IdentityReference -Path $script:testDirPath -Inherited -Permission $_.FileSystemRights) | Should -BeTrue
            }
    }

    It 'should handle revoking non existent permission' {
        Revoke-CPermission -Path $script:testDirPath -Identity $script:username
        (Test-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl') | Should -BeFalse
        Revoke-CPermission -Path $script:testDirPath -Identity $script:username
        $Global:Error.Count | Should -Be 0
        (Test-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl') | Should -BeFalse
    }

    It 'should resolve relative path' {
        Push-Location -Path (Split-Path -Parent -Path $script:testDirPath)
        try
        {
            Revoke-CPermission -Path ('.\{0}' -f (Split-Path -Leaf -Path $script:testDirPath)) -Identity $script:username
            (Test-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl') | Should -BeFalse
        }
        finally
        {
            Pop-Location
        }
    }

    It 'should support what if' {
        Revoke-CPermission -Path $script:testDirPath -Identity $script:username -WhatIf
        (Test-CPermission -Path $script:testDirPath -Identity $script:username -Permission 'FullControl') | Should -BeTrue
    }

    It 'should revoke permission on registry' {
        $regKey = 'hkcu:\TestRevokePermissions'
        New-Item $regKey

        try
        {
            Grant-CPermission -Identity $script:username -Permission 'ReadKey' -Path $regKey
            $result = Revoke-CPermission -Path $regKey -Identity $script:username
            $result | Should -BeNullOrEmpty
            (Test-CPermission -Path $regKey -Identity $script:username -Permission 'ReadKey') | Should -BeFalse
        }
        finally
        {
            Remove-Item $regKey
        }
    }

    It 'should revoke local machine private key permissions' {
        $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation LocalMachine -StoreName My -PassThru
        try
        {
            $certPath = Join-Path -Path 'cert:\LocalMachine\My' -ChildPath $cert.Thumbprint
            Grant-CPermission -Path $certPath -Identity $script:username -Permission 'FullControl'
            (Get-CPermission -Path $certPath -Identity $script:username) | Should -Not -BeNullOrEmpty
            Revoke-CPermission -Path $certPath -Identity $script:username
            $Global:Error.Count | Should -Be 0
            (Get-CPermission -Path $certPath -Identity $script:username) | Should -BeNullOrEmpty
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation LocalMachine -StoreName My
        }
    }

    It 'should revoke current user private key permissions' {
        $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
        try
        {
            $certPath = Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $cert.Thumbprint
            Grant-CPermission -Path $certPath -Identity $script:username -Permission 'FullControl' -WhatIf
            $Global:Error.Count | Should -Be 0
            (Get-CPermission -Path $certPath -Identity $script:username) | Should -BeNullOrEmpty
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
        }
    }

    It 'should support what if when revoking private key permissions' {
        $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation LocalMachine -StoreName My -PassThru
        try
        {
            $certPath = Join-Path -Path 'cert:\LocalMachine\My' -ChildPath $cert.Thumbprint
            Grant-CPermission -Path $certPath -Identity $script:username -Permission 'FullControl'
            (Get-CPermission -Path $certPath -Identity $script:username) | Should -Not -BeNullOrEmpty
            Revoke-CPermission -Path $certPath -Identity $script:username -WhatIf
            $Global:Error.Count | Should -Be 0
            (Get-CPermission -Path $certPath -Identity $script:username) | Should -Not -BeNullOrEmpty
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation LocalMachine -StoreName My
        }
    }

    It 'revokes permission on cng certificate' {
        $cngCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\CarbonRsaCng.pfx' -Resolve
        $cert = Install-CCertificate -Path $cngCertPath -StoreLocation LocalMachine -StoreName My -PassThru
        try
        {
            $certPath = Join-Path -Path 'cert:\LocalMachine\My' -ChildPath $cert.Thumbprint
            Grant-CPermission -Path $certPath -Identity $script:username -Permission 'FullControl'
            Get-CPermission -Path $certPath -Identity $script:username | Should -Not -BeNullOrEmpty
            Revoke-CPermission -Path $certPath -Identity $script:username
            $Global:Error.Count | Should -Be 0
            Get-CPermission -Path $certPath -Identity $script:username | Should -BeNullOrEmpty
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation LocalMachine -StoreName My
        }
    }

}
