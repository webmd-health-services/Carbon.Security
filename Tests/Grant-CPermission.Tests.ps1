
using namespace System.Security.AccessControl

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $psModulesSharedPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Permissions\Modules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesSharedPath -ChildPath 'Carbon.Core' -Resolve) `
                  -Function ('Get-CPathProvider') `
                  -Global `
                  -Verbose:$false
    Import-Module -Name (Join-Path -Path $psModulesSharedPath -ChildPath 'Carbon.Accounts' -Resolve) `
                  -Function ('Resolve-CIdentityName') `
                  -Global `
                  -Verbose:$false

    $script:testDirPath = $null
    $script:testNum = 0

    $Path = $null
    $script:user = 'CarbonGrantPerms'
    $script:user2 = 'CarbonGrantPerms2'
    $containerPath = $null
    $regContainerPath = $null

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
            $Type
        )

        $grantArgs = @{ }
        $thenArgs = @{
            HasInheritanceFlags = ([InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit);
            HasPropagationFlags = [PropagationFlags]::None;
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
        $result = Grant-CPermission -Identity 'BUILTIN\Administrators' -Permission 'BlahBlahBlah' -Path $path -PassThru -ErrorAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        $Global:Error.Count | Should -Be 1
        $Global:Error | Should -Match 'permission is invalid or unknown'
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

    $testCases = @(
        # Apply deep.
        @{
            ApplyTo = 'ContainerOnly';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::None;
            PropagationFlags = [PropagationFlags]::None;
        },
        @{
            ApplyTo = 'ContainerSubcontainersAndLeaves';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::None;
        },
        @{
            ApplyTo = 'ContainerAndSubcontainers';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit;
            PropagationFlags = [PropagationFlags]::None;
        },
        @{
            ApplyTo = 'ContainerAndLeaves';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::None;
        },
        @{
            ApplyTo = 'SubcontainersAndLeavesOnly';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly;
        },
        @{
            ApplyTo = 'SubcontainersOnly';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly;
        },
        @{
            ApplyTo = 'LeavesOnly';
            OnlyApplyToChildren = $false;
            InheritanceFlags = [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly;
        },
        # Apply only to children/one level.
        @{
            ApplyTo = 'ContainerOnly';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::None;
            PropagationFlags = [PropagationFlags]::None;
        },
        @{
            ApplyTo = 'ContainerSubcontainersAndLeaves';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::NoPropagateInherit;
        },
        @{
            ApplyTo = 'ContainerAndSubcontainers';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit;
            PropagationFlags = [PropagationFlags]::NoPropagateInherit;
        },
        @{
            ApplyTo = 'ContainerAndLeaves';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::NoPropagateInherit;
        },
        @{
            ApplyTo = 'SubcontainersAndLeavesOnly';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly -bor [PropagationFlags]::NoPropagateInherit;
        },
        @{
            ApplyTo = 'SubcontainersOnly';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ContainerInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly -bor [PropagationFlags]::NoPropagateInherit;
        },
        @{
            ApplyTo = 'LeavesOnly';
            OnlyApplyToChildren = $true;
            InheritanceFlags = [InheritanceFlags]::ObjectInherit;
            PropagationFlags = [PropagationFlags]::InheritOnly -bor [PropagationFlags]::NoPropagateInherit;
        }
    )


    It 'sets flags for applies <ApplyTo> and apply only to children <OnlyApplyToChildren>' -TestCases $testCases {
        $path = GivenDirectory
        Grant-CPermission -Identity $script:user `
                          -Permission Read `
                          -Path $path `
                          -ApplyTo $ApplyTo `
                          -OnlyApplyToChildren:$OnlyApplyToChildren
        ThenPermission -On $path `
                       -For $script:user `
                       -Is ([FileSystemRights]::Read -bor [FileSystemRights]::Synchronize) `
                       -HasInheritanceFlag $InheritanceFlags `
                       -HasPropagationFlag $PropagationFlags
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
        $containerPath = New-TestContainer -FileSystem

        Grant-CPermission -Identity $script:user `
                          -Permission FullControl `
                          -Path $containerPath `
                          -ApplyTo ContainerAndLeaves `
                          -OnlyApplyToChildren
        ThenPermission -On $containerPath `
                       -For $script:user `
                       -Is ([FileSystemRights]::FullControl) `
                       -HasInheritanceFlags [InheritanceFlags]::ObjectInherit `
                       -HasPropagationFlags [PropagationFlags]::NoPropagateInherit

        Mock -CommandName 'Set-Acl' -Verifiable -ModuleName 'Carbon.Permissions'

        Grant-CPermission -Identity $script:user `
                          -Permission FullControl `
                          -Path $containerPath `
                          -ApplyTo ContainerAndLeaves `
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
        $Global:Error | Should -HaveCount 1
        $Global:Error | Should -Match 'path does not exist'
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
        Grant-CPermission -Path $dirPath `
                          -Identity $script:user `
                          -Permission 'Write' `
                          -ApplyTo ContainerAndLeaves `
                          -Append
        $perm = Get-CPermission -Path $dirPath -Identity $script:user
        $perm | Should -HaveCount 2
    }
}
