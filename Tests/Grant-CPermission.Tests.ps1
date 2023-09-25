
using namespace System.Security.AccessControl

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $psModulesSharedPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Permissions\Modules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesSharedPath -ChildPath 'Carbon.Core' -Resolve) `
                  -Function ('Get-CPathProvider') `
                  -Global
    Import-Module -Name (Join-Path -Path $psModulesSharedPath -ChildPath 'Carbon.Accounts' -Resolve) `
                  -Function ('Resolve-CIdentityName') `
                  -Global
    $psModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSModules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesPath -ChildPath 'Carbon.Cryptography' -Resolve) `
                  -Function ('Install-CCertificate', 'Uninstall-CCertificate') `
                  -Global

    $script:testDirPath = $null
    $script:testNum = 0

    $Path = $null
    $script:user = 'CarbonGrantPerms'
    $script:user2 = 'CarbonGrantPerms2'
    $containerPath = $null
    $regContainerPath = $null
    $script:privateKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\CarbonTestPrivateKey.pfx' -Resolve

    function Assert-InheritanceFlags
    {
        param(
            [string]
            $ContainerInheritanceFlags,

            [Security.AccessControl.InheritanceFlags]
            $InheritanceFlags,

            [Security.AccessControl.PropagationFlags]
            $PropagationFlags
        )

        $ace = Get-CPermission $containerPath -Identity $script:user

        $ace | Should -Not -BeNullOrEmpty
        $writeRights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Synchronize
        $ace.FileSystemRights | Should -Be $writeRights
        $ace.InheritanceFlags | Should -Be $InheritanceFlags
        $ace.PropagationFlags | Should -Be $PropagationFlags
    }

    function GivenDirectory
    {
        return (New-TestContainer -FileSystem)
    }

    function Invoke-GrantPermissions
    {
        [CmdletBinding()]
        param(
            $Identity,
            $Permissions,
            $Path,
            [ValidateSet('FileSystem', 'Registry', 'CryptoKey')]
            $ProviderName = 'FileSystem',
            [switch] $Clear,
            $ExpectedPermission,
            $Type,
            $WithInheritanceFlags,
            $WithPropagationFlags
        )

        $grantArgs = @{ }
        $thenArgs = @{
            HasInheritanceFlags = ([InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit);
            HasPropagationFlags = [PropagationFlags]::None;
        }

        if ($PSBoundParameters.ContainsKey('WithInheritanceFlags'))
        {
            $grantArgs['InheritanceFlag'] = $WithInheritanceFlags
            $thenArgs['HasInheritanceFlags'] = $WithInheritanceFlags
        }

        if ($PSBoundParameters.ContainsKey('WithPropagationFlag'))
        {
            $grantArgs['PropagationFlag'] = $WithPropagationFlags
            $thenArgs['HasPropagationFlags'] = $WithPropagationFlags
        }

        if( $Clear )
        {
            $grantArgs['Clear'] = $Clear
        }

        if( $Type )
        {
            $grantArgs['Type'] = $Type
            $thenArgs['OfType'] = $Type
        }

        $expectedRuleType = ('Security.AccessControl.{0}AccessRule' -f $ProviderName) -as [Type]
        $result = Grant-CPermission -Identity $Identity -Permission $Permissions -Path $path -PassThru @grantArgs
        $result = $result | Select-Object -Last 1
        $result | Should -Not -BeNullOrEmpty
        $result.IdentityReference | Should -Be (Resolve-CIdentityName $Identity)
        $result | Should -BeOfType $expectedRuleType
        if( -not $ExpectedPermission )
        {
            $ExpectedPermission = $Permissions
        }

        ThenPermission -On $Path -For $Identity -Is $ExpectedPermission @thenArgs
    }

    function New-TestContainer
    {
        param(
            [Switch]
            $FileSystem,
            [Switch]
            $Registry
        )

        if( $FileSystem )
        {
            $path = Join-Path -Path $script:testDirPath -ChildPath ([IO.Path]::GetRandomFileName())
            New-Item -Path $path -ItemType 'Directory' -Force -ErrorAction Ignore | Out-Null
            return $path
        }

        if( $Registry )
        {
            $regContainerPath = 'hkcu:\CarbonTestGrantPermission{0}' -f ([IO.Path]::GetRandomFileName())
            $key = New-Item -Path $regContainerPath
            return $regContainerPath
        }
    }

    function New-TestFile
    {
        param(
        )

        $containerPath = New-TestContainer -FileSystem

        $leafPath = Join-Path -Path $containerPath -ChildPath ([IO.Path]::GetRandomFileName())
        New-Item -ItemType 'File' -Path $leafPath | Out-Null
        return $leafPath
    }

    function ThenPermission
    {
        [CmdletBinding()]
        param(
            [String] $On,
            [String] $For,
            [Object] $Is,
            [AccessControlType] $OfType,
            $HasInheritanceFlags,
            $HasPropagationFlags
        )

        if (-not $OfType)
        {
            $OfType = [AccessControlType]::Allow
        }

        $provider = Get-CPathProvider -Path $On
        $expectedPermission = [FileSystemRights]0
        $rightsPropertyName = 'FileSystemRights'
        if ($provider.Name -eq 'Registry')
        {
            $expectedPermission = [RegistryRights]0
            $rightsPropertyName = 'RegistryRights'
        }
        elseif ($provider.Name -eq 'Certificate')
        {
            if ((Invoke-TestCCryptoKeyAvailable) -and $Is -isnot [FileSystemRights])
            {
                $expectedPermission = [CryptoKeyRights]0
                $rightsPropertyName = 'CryptoKeyRights'
            }
        }

        $Is | ForEach-Object { $expectedPermission = $expectedPermission -bor $_ }
        if ($rightsPropertyName -eq 'FileSystemRights' -and $OfType -eq [AccessControlType]::Allow)
        {
            $expectedPermission = $expectedPermission -bor [FileSystemRights]::Synchronize
        }

        $perm = Get-CPermission -Path $On -Identity $For
        $perm | Should -Not -BeNullOrEmpty
        $perm.AccessControlType | Should -Be $OfType
        $perm.$rightsPropertyName | Should -Be $expectedPermission
        if ($PSBoundParameters.ContainsKey('HasInheritanceFlag'))
        {
            $perm.InheritanceFlags | Should -Be $HasInheritanceFlag
        }
        if ($PSBoundParameters.ContainsKey('HasPropagationFlag'))
        {
            $perm.PropagationFlags | Should -Be $HasPropagationFlag
        }
    }
}

Describe 'Grant-CPermission' {
    BeforeEach {
        $Global:Error.Clear()
        $script:testDirPath = Join-Path -Path $TestDrive -ChildPath $script:testNum
        New-Item -Path $script:testDirPath -ItemType 'Directory'
    }

    AfterEach {
        $script:testNum += 1
    }

    It 'when changing permissions on a file' {
        $file = New-TestFile
        $identity = 'BUILTIN\Administrators'
        $permissions = [FileSystemRights]::Read,[FileSystemRights]::Write

        Invoke-GrantPermissions -Identity $identity -Permissions $permissions -Path $file
        ThenPermission -On $file -For $identity -Is $permissions
    }

    It 'when changing permissions on a directory' {
        $dir = New-TestContainer -FileSystem
        $identity = 'BUILTIN\Administrators'
        $permissions = 'Read','Write'

        Invoke-GrantPermissions -Identity $identity -Permissions $permissions -Path $dir
        ThenPermission -On $dir -For $identity -Is $permissions
    }

    It 'when changing permissions on registry key' {
        $regKey = New-TestContainer -Registry

        Invoke-GrantPermissions -Identity 'BUILTIN\Administrators' `
                                -Permission 'ReadKey' `
                                -Path $regKey `
                                -ProviderName 'Registry'
        ThenPermission -On $regKey -For 'BUILTIN\Administrators' -Is ([RegistryRights]::ReadKey)
    }

    It 'when passing an invalid permission' {
        $path = New-TestFile
        $error.Clear()
        $result = Grant-CPermission -Identity 'BUILTIN\Administrators' -Permission 'BlahBlahBlah' -Path $path -PassThru -ErrorAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        $error.Count | Should -Be 2
    }

    It 'when clearing existing permissions' {
        $path = New-TestFile
        Invoke-GrantPermissions $script:user 'FullControl' -Path $path
        ThenPermission -On $path -For $script:user -Is ([FileSystemRights]::FullControl)
        Invoke-GrantPermissions $script:user2 'FullControl' -Path $path
        ThenPermission -On $path -For $script:user2 -Is ([FileSystemRights]::FullControl)

        $result = Grant-CPermission -Identity 'Everyone' -Permission 'Read','Write' -Path $path -Clear -PassThru
        $result | Should -Not -BeNullOrEmpty
        $result.Path | Should -Be $Path

        $acl = Get-Acl -Path $path

        $rules = $acl.Access |
                    Where-Object { -not $_.IsInherited }
        $rules | Should -Not -BeNullOrEmpty
        $rules.IdentityReference.Value | Should -Be 'Everyone'
    }

    It 'when there are no existing permissions to clear' {
        $Global:Error.Clear()

        $path = New-TestFile

        $acl = Get-Acl -Path $path
        $rules = $acl.Access | Where-Object { -not $_.IsInherited }
        if( $rules )
        {
            $rules | ForEach-Object { $acl.RemoveAccessRule( $_ ) }
            Set-Acl -Path $path -AclObject $acl
        }

        $error.Clear()
        $result = Grant-CPermission -Identity 'Everyone' -Permission 'Read','Write' -Path $path -Clear -PassThru -ErrorAction SilentlyContinue
        $result | Should -Not -BeNullOrEmpty
        $result.IdentityReference | Should -Be 'Everyone'

        $error.Count | Should -Be 0

        $acl = Get-Acl -Path $path
        $rules = $acl.Access | Where-Object { -not $_.IsInherited }
        $rules | Should -Not -BeNullOrEmpty
        ($rules.IdentityReference.Value -like 'Everyone') | Should -BeTrue
    }

    $inheritanceFlags = [Enum]::GetValues([InheritanceFlags])
    Context 'inheritance flag <_>' -ForEach $inheritanceFlags {
        $inheritanceFlag = $_
        $propagationFlags =
            [Enum]::GetValues([PropagationFlags]) |
            ForEach-Object { @{ PropagationFlag = $_ ; InheritanceFlag = $inheritanceFlag }}

        Context 'propagation flag <propagationFlag>' -ForEach $propagationFlags {
            It 'sets inheritance and propagation flags' {
                $path = GivenDirectory
                Grant-CPermission -Identity $script:user `
                                  -Permission Read `
                                  -Path $path `
                                  -InheritanceFlag $InheritanceFlag `
                                  -PropagationFlag $PropagationFlag
                $expectedPropagationFlag = $PropagationFlag
                if ($InheritanceFlag -eq [InheritanceFlags]::None)
                {
                    $expectedPropagationFlag = [PropagationFlags]::None
                }
                ThenPermission -On $path `
                               -For $script:user `
                               -Is ([FileSystemRights]::Read -bor [FileSystemRights]::Synchronize) `
                               -HasInheritanceFlag $InheritanceFlag `
                               -HasPropagationFlag $expectedPropagationFlag
            }
        }
    }

    It 'when a user already has a different permission' {
        $containerPath = New-TestContainer -FileSystem
        Invoke-GrantPermissions -Identity $script:user -Permission FullControl -Path $containerPath
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::FullControl)
        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $containerPath
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::Read)
    }

    It 'when a user already has the permissions' {
        $containerPath = New-TestContainer -FileSystem

        Invoke-GrantPermissions -Identity $script:user -Permission FullControl -Path $containerPath
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::FullControl)

        Mock -CommandName 'Set-Acl' -Verifiable -ModuleName 'Carbon.Permissions'

        Invoke-GrantPermissions -Identity $script:user -Permission FullControl -Path $containerPath
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::FullControl)
        Should -Invoke 'Set-Acl' -Times 0 -ModuleName 'Carbon.Permissions'
    }

    It 'when forcing a permission change and the user already has the permissions' {
        $Global:VerbosePreference = $Global:DebugPreference = 'Continue'
        $containerPath = New-TestContainer -FileSystem

        Invoke-GrantPermissions -Identity $script:user `
                                -Permission FullControl `
                                -Path $containerPath `
                                -WithInheritanceFlags ObjectInherit `
                                -WithPropagationFlags None
        ThenPermission -On $containerPath `
                       -For $script:user `
                       -Is ([FileSystemRights]::FullControl) `
                       -HasInheritanceFlags ObjectInherit `
                       -HasPropagationFlags None

        Mock -CommandName 'Set-Acl' -Verifiable -ModuleName 'Carbon.Permissions'

        Grant-CPermission -Identity $script:user `
                           -Permission FullControl `
                           -Path $containerPath `
                           -InheritanceFlag ([InheritanceFlags]::ObjectInherit) `
                           -PropagationFlag ([PropagationFlags]::None) `
                           -Force

        Should -Invoke 'Set-Acl' -Times 1 -Exactly -ModuleName 'Carbon.Permissions'
    }

    It 'when an item is hidden' {
        $Global:VerbosePreference = $Global:DebugPreference = 'SilentlyContinue'

        $path = New-TestFile
        $item = Get-Item -Path $path
        $item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden

        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $path
        ThenPermission -On $path -For $script:user -Is ([FileSystemRights]::Read)
        $Global:Error.Count | Should -Be 0
    }

    It 'when the path does not exist' {
        $result = Grant-CPermission -Identity $script:user -Permission Read -Path 'C:\I\Do\Not\Exist' -PassThru -ErrorAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'Cannot find path'
    }

    It 'when clearing a permission that already exists on a file' {
        $path = New-TestFile
        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $Path
        ThenPermission -On $path -For $script:user -Is ([FileSystemRights]::Read)
        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $Path -Clear
        ThenPermission -On $path -For $script:user -Is ([FileSystemRights]::Read)
        $Global:Error | Should -BeNullOrEmpty
    }

    It 'when clearing permissions that already exist on a directory' {

        $containerPath = New-TestContainer -FileSystem

        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $containerPath
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::Read)
        Invoke-GrantPermissions -Identity $script:user -Permission Read -Path $containerPath -Clear
        ThenPermission -On $containerPath -For $script:user -Is ([FileSystemRights]::Read)

        $Global:Error | Should -BeNullOrEmpty
    }

    It 'when clearing permissions that already exist on a registry key' {
        $regContainerPath = New-TestContainer -Registry
        Invoke-GrantPermissions -Identity $script:user -Permission ReadKey -Path $regContainerPath -ProviderName 'Registry'
        ThenPermission -On $regContainerPath -For $script:user -Is ([RegistryRights]::ReadKey)
        Invoke-GrantPermissions -Identity $script:user `
                                -Permission QueryValues `
                                -Path $regContainerPath `
                                -ProviderName 'Registry' `
                                -Clear
        ThenPermission -On $regContainerPath -For $script:user -Is ([RegistryRights]::QueryValues)

        $Global:Error | Should -BeNullOrEmpty
    }

    $skip = (Test-Path -Path 'env:WHS_CI') -and $env:WHS_CI -eq 'True' -and $PSVersionTable['PSVersion'].Major -eq 7
    $testCases = @('LocalMachine', 'CurrentUser')
    It 'when setting permissions on a private key in the <_> location' -TestCases $testCases -Skip:$skip {
        $location = $_
        $cert = Install-CCertificate -Path $script:privateKeyPath -StoreLocation $location -StoreName My -PassThru
        try
        {
            $certPath = Join-Path -Path ('cert:\{0}\My' -f $location) -ChildPath $cert.Thumbprint

            # CryptoKey does not exist in .NET standard/core so we will have to use FileSystem instead
            if ((Invoke-TestCCryptoKeyAvailable))
            {
                $expectedProviderName = 'CryptoKey'
                $readPermission = 'GenericRead'
                $readRights = [CryptoKeyRights]::GenericRead,[CryptoKeyRights]::Synchronize
                $readRightsForDeny = [CryptoKeyRights]::GenericRead
                $writePermission = 'GenericWrite'
                # $expectedPerm = 'GenericAll'
                $writeRights = [CryptoKeyRights]::GenericAll,[CryptoKeyRights]::GenericRead,[CryptoKeyRights]::Synchronize
            }
            else
            {
                $expectedProviderName = 'FileSystem'
                $readPermission = 'Read'
                $readRights = [FileSystemRights]::Read
                $readRightsForDeny = [FileSystemRights]::Read
                $writePermission = 'Write'
                $writeRights = [FileSystemRights]::Write
            }

            $cert | Should -Not -BeNullOrEmpty

            # Context 'adds permissions' {
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user `
                                    -Permission $writePermission `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $writeRights
            ThenPermission -On $certPath -For $script:user -Is $writeRights

            # Context 'changes permissions' {
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user `
                                    -Permission $readPermission `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $readRights
            ThenPermission -On $certPath -For $script:user -Is $readRights

            # Context 'clearing others'' permissions' {
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user2 `
                                    -Permission $readPermission `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $readRights `
                                    -Clear
            ThenPermission -On $certPath -For $script:user2 -Is $readRights
            Test-CPermission -Path $certPath -Identity $script:user -Permission $readPermission | Should -BeFalse

            # Context 'clearing others'' permissions when permissions getting set haven''t changed' {
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user `
                                    -Permission $readPermission `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $readRights
            ThenPermission -On $certPath -For $script:user -Is $readRights
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user2 `
                                    -Permission $readPermission `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $readRights `
                                    -Clear
            ThenPermission -On $certPath -For $script:user2 -Is $readRights
            Test-CPermission -Path $certPath -Identity $script:user -Permission $readPermission | Should -BeFalse

            # Context 'running with -WhatIf switch' {
            Grant-CPermission -Path $certPath -Identity $script:user2 -Permission $writePermission -WhatIf
            Test-CPermission -Path $certPath -Identity $script:user2 -Permission $readPermission -Exact | Should -BeTrue
            Test-CPermission -Path $certPath -Identity $script:user2 -Permission $writePermission -Exact | Should -BeFalse

            # Context 'creating a deny rule' {
            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user `
                                    -Permission $readPermission `
                                    -Type 'Deny' `
                                    -ProviderName $expectedProviderName `
                                    -ExpectedPermission $readRightsForDeny
            ThenPermission -On $certPath -For $script:user -Is $readRightsForDeny -OfType Deny

            # CryptoKey does not exist in .NET standard/core
            if( (Invoke-TestCCryptoKeyAvailable) )
            {
                Mock -CommandName 'Set-CCryptoKeySecurity' -Verifiable -ModuleName 'Carbon.Permissions'

                # Context 'permissions exist' {
                # Now, check that permissions don't get re-applied.
                Grant-CPermission -Path $certPath -Identity $script:user2 -Permission $readPermission
                Should -Invoke 'Set-CCryptoKeySecurity' -ModuleName 'Carbon.Permissions' -Times 0

                # Context 'permissions exist but forcing the change' {
                Grant-CPermission -Path $certPath -Identity $script:user2 -Permission $readPermission -Force
                Should -Invoke 'Set-CCryptoKeySecurity' -ModuleName 'Carbon.Permissions' -Times 1 -Exactly
            }
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation $location -StoreName My
        }
    }

    It 'grants permissions to cng key' {
        $certPath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\CarbonRsaCng.pfx' -Resolve
        $cert = Install-CCertificate -Path $certPath -StoreLocation CurrentUser -StoreName My -PassThru
        $expectedRights = [FileSystemRights]::Write

        try
        {
            $certPath = Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $cert.Thumbprint

            $cert | Should -Not -BeNullOrEmpty

            Invoke-GrantPermissions -Path $certPath `
                                    -Identity $script:user `
                                    -Permission 'GenericWrite' `
                                    -ProviderName 'FileSystem' `
                                    -ExpectedPermission $expectedRights
            ThenPermission -On $certPath -For $script:user -Is $expectedRights
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
        }
    }

    It 'when setting Deny rule on file system' {
        $filePath = New-TestFile
        Invoke-GrantPermissions -Identity $script:user -Permissions 'Write' -Path $filePath -Type 'Deny'
        ThenPermission -On $filePath -For $script:user -Is ([FileSystemRights]::Write) -OfType Deny
    }

    It 'when setting Deny rule on registry' {
        $path = New-TestContainer -Registry
        Invoke-GrantPermissions -Identity $script:user -Permissions 'Write' -Path $path -Type 'Deny' -ProviderName 'Registry'
        ThenPermission -On $path -For $script:user -Is ([RegistryRights]::WriteKey) -OfType Deny
    }

    It 'when granting multiple different rules to a user on the file system' {
        $dirPath = New-TestContainer -FileSystem
        Grant-CPermission -Path $dirPath -Identity $script:user -Permission 'Read' -Append
        Grant-CPermission -Path $dirPath -Identity $script:user -Permission 'Write' -InheritanceFlag ObjectInherit -PropagationFlag None -Append
        $perm = Get-CPermission -Path $dirPath -Identity $script:user
        $perm | Should -HaveCount 2
    }
}
