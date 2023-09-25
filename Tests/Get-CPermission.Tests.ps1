
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules\Carbon.Cryptography' -Resolve) `
                  -Function ('Install-CCertificate', 'Uninstall-CCertificate') `
                  -Global `
                  -Verbose:$false

    $script:user = 'CarbonTestUser1'
    $script:group1 = 'CarbonTestGroup1'
    $script:containerPath = $null
    $script:childPath = $null

    function Get-CertificateWithPrivateKey
    {
        Get-Item -Path 'Cert:\*\*' |
            Where-Object 'Name' -NotIn @('UserDS') | # This store causes problems on PowerShell 7.
            Get-ChildItem |
            Where-Object 'PsIsContainer' -EQ $false |
            Where-Object 'HasPrivateKey' -EQ $true |
            Where-Object 'PrivateKey' -NE $null |
            # Couldn't get perms on a cert with this usage.
            Where-Object { -not ($_.EnhancedKeyUsageList | Where-Object 'FriendlyName' -EQ 'Smart Card Logon') }
    }
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

    It 'should get private cert permission' {
        $certs = Get-CertificateWithPrivateKey
        foreach ($cert in $certs)
        {
            $expectedType = [Security.AccessControl.FileSystemAccessRule]
            if ($cert.PrivateKey -and `
                ($cert.PrivateKey | Get-Member -Name 'CspKeyContainerInfo') -and `
                [Type]::GetType('System.Security.AccessControl.CryptoKeyAccessRule'))
            {
                $expectedType = [Security.AccessControl.CryptoKeyAccessRule]
            }
            $certPath = Join-Path -Path 'cert:' -ChildPath ($cert.PSPath | Split-Path -NoQualifier)
            $numErrors = $Global:Error.Count
            $perms = Get-CPermission -Path $certPath -Inherited -ErrorAction SilentlyContinue
            if ($numErrors -ne $Global:Error.Count -and `
                ($Global:Error[0] -match '(keyset does not exist)|(Invalid provider type specified)'))
            {
                continue
            }
            $perms | Should -Not -BeNullOrEmpty -Because "${certPath} should have private key permissions"
            $perms | Should -BeOfType $expectedType
        }
    }

    It 'should get specific identity cert permission' {
        Get-CertificateWithPrivateKey |
            ForEach-Object { Join-Path -Path 'cert:' -ChildPath (Split-Path -NoQualifier -Path $_.PSPath) } |
            ForEach-Object {
                [Object[]]$rules = Get-CPermission -Path $_
                foreach( $rule in $rules )
                {
                    [Object[]]$identityRule = Get-CPermission -Path $_ -Identity $rule.IdentityReference.Value
                    $identityRule | Should -Not -BeNullOrEmpty
                    $identityRule.Count | Should -BeLessOrEqual $rules.Count
                }
            }
    }

    It 'gets permissions for cng private key' {
        $certFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\CarbonRsaCng.pfx' -Resolve
        $cert = Install-CCertificate -Path $certFilePath -StoreLocation CurrentUser -StoreName My -PassThru
        try
        {
            $perms =
                Get-CPermission -Path (Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $cert.Thumbprint) -Inherited
            $perms | Should -Not -BeNullOrEmpty
            $perms | Should -BeOfType [Security.AccessControl.FileSystemAccessRule]
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
        }
    }
}
