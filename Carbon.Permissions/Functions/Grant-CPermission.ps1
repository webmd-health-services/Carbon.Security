 function Grant-CPermission
{
    <#
    .SYNOPSIS
    Grants permissions on a file, directory, or registry key.

    .DESCRIPTION
    The `Grant-CPermission` function grants permissions to files, directories, or registry keys. Using this function and
    module are not recommended. Instead,

    * for file/directory permissions, use `Grant-CNtfsPermission` in the `Carbon.FileSystem` module.
    * for registry permissions, use `Grant-CRegistryPermission` in the `Carbon.Registry` module.
    * for private key and/or key container permissions, use `Grant-CPrivateKeyPermission` in the `Carbon.Cryptography`
      module.

    Pass the item's path to the `Path` parameter, the name of the user/group receiving the permission to the `Identity`
    parameter, and the permission to grant to the `Permission` parameter. If the identity doesn't have the permission,
    the item's ACL is updated to include the new permission. If the identity has permission, but it doesn't match the
    permission being set, the identity's current permissions are changed to match. If the identity already has the given
    permission, nothing happens. Inherited permissions are ignored. To always grant permissions, use the `Force`
    (switch).

    The `Permissions` attribute should be a list of
    [FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx) or
    [RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx), for
    files/directories or registry keys, respectively. These commands will show you the values for the appropriate
    permissions for your object:

        [Enum]::GetValues([Security.AccessControl.FileSystemRights])
        [Enum]::GetValues([Security.AccessControl.RegistryRights])

    To get back the access rule, use the `PassThru` switch.

    By default, an `Allow` access rule is created and granted. To create a `Deny` access rule, pass `Deny` to the `Type`
    parameter.

    To append/add permissions instead of replacing existing permissions, use the `Append` switch.

    To control how the permission is applied and inherited, use the `ApplyTo` and `OnlyApplyToChildren` parameters.
    These behave like the "Applies to" and "Only apply these permissions to objects and/or containers within this
    container" fields in the Windows Permission user interface. The following table shows how these parameters are
    converted to `[Security.AccesControl.InheritanceFlags]` and `[Security.AccessControl.PropagationFlags]` values:

    | ApplyTo                         | OnlyApplyToChildren | InheritanceFlags                | PropagationFlags
    | ------------------------------- | ------------------- | ------------------------------- | ----------------
    | ContainerOnly                   | false               | None                            | None
    | ContainerSubcontainersAndLeaves | false               | ContainerInherit, ObjectInherit | None
    | ContainerAndSubcontainers       | false               | ContainerInherit                | None
    | ContainerAndLeaves              | false               | ObjectInherit                   | None
    | SubcontainersAndLeavesOnly      | false               | ContainerInherit, ObjectInherit | InheritOnly
    | SubcontainersOnly               | false               | ContainerInherit                | InheritOnly
    | LeavesOnly                      | false               | ObjectInherit                   | InheritOnly
    | ContainerOnly                   | true                | None                            | None
    | ContainerSubcontainersAndLeaves | true                | ContainerInherit, ObjectInherit | NoPropagateInherit
    | ContainerAndSubcontainers       | true                | ContainerInherit                | NoPropagateInherit
    | ContainerAndLeaves              | true                | ObjectInherit                   | NoPropagateInherit
    | SubcontainersAndLeavesOnly      | true                | ContainerInherit, ObjectInherit | NoPropagateInherit, InheritOnly
    | SubcontainersOnly               | true                | ContainerInherit                | NoPropagateInherit, InheritOnly
    | LeavesOnly                      | true                | ObjectInherit                   | NoPropagateInherit, InheritOnly

    .OUTPUTS
    System.Security.AccessControl.AccessRule. When setting permissions on a file or directory, a
    `System.Security.AccessControl.FileSystemAccessRule` is returned. When setting permissions on a registry key, a
    `System.Security.AccessControl.RegistryAccessRule` returned.

    .LINK
    Get-CPermission

    .LINK
    Revoke-CPermission

    .LINK
    Test-CPermission

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/magazine/cc163885.aspx#S3

    .EXAMPLE
    Grant-CPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Path C:\EngineRoom

    Grants the Enterprise's engineering group full control on the engine room.  Very important if you want to get
    anywhere.

    .EXAMPLE
    Grant-CPermission -Identity ENTERPRISE\Interns -Permission ReadKey,QueryValues,EnumerateSubKeys -Path rklm:\system\WarpDrive

    Grants the Enterprise's interns access to read about the warp drive.  They need to learn someday, but at least they
    can't change anything.

    .EXAMPLE
    Grant-CPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Path C:\EngineRoom -Clear

    Grants the Enterprise's engineering group full control on the engine room.  Any non-inherited, existing access rules
    are removed from `C:\EngineRoom`.

    .EXAMPLE
    Grant-CPermission -Identity BORG\Locutus -Permission FullControl -Path 'C:\EngineRoom' -Type Deny

    Demonstrates how to grant deny permissions on an objecy with the `Type` parameter.

    .EXAMPLE
    Grant-CPermission -Path C:\Bridge -Identity ENTERPRISE\Wesley -Permission 'Read' -ApplyTo ContainerAndSubContainersAndLeaves -Append
    Grant-CPermission -Path C:\Bridge -Identity ENTERPRISE\Wesley -Permission 'Write' -ApplyTo ContainerAndLeaves
    -Append

    Demonstrates how to grant multiple access rules to a single identity with the `Append` switch. In this case,
    `ENTERPRISE\Wesley` will be able to read everything in `C:\Bridge` and write only in the `C:\Bridge` directory, not
    to any sub-directory.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='ApplyToContainersSubcontainersAndLeaves')]
    [OutputType([Security.AccessControl.AccessRule])]
    param(
        # The path on which the permissions should be granted.  Can be a file system or registry path. If the path is
        # relative, it uses the current location to determine the full path.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user or group getting the permissions.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The permission: e.g. FullControl, Read, etc.  For file system items, use values from
        # [System.Security.AccessControl.FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx).
        # For registry items, use values from
        # [System.Security.AccessControl.RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx).
        [Parameter(Mandatory)]
        [String[]] $Permission,

        # How the permissions should be applied recursively to subcontainers and leaves. Default is
        # `ContainerSubcontainersAndLeaves`.
        [Parameter(Mandatory, ParameterSetName='IncludeAppliesTo')]
        [ValidateSet('ContainerOnly', 'ContainerSubcontainersAndLeaves', 'ContainerAndSubcontainers',
            'ContainerAndLeaves', 'SubcontainersAndLeavesOnly', 'SubcontainersOnly', 'LeavesOnly')]
        [String] $ApplyTo,

        # Inherited permissions should only apply to the children of the container, i.e. only one level deep.
        [Parameter(ParameterSetName='IncludeAppliesTo')]
        [switch] $OnlyApplyToChildren,

        # The type of rule to apply, either `Allow` or `Deny`. The default is `Allow`, which will allow access to the
        # item. The other option is `Deny`, which will deny access to the item.
        [AccessControlType] $Type = [AccessControlType]::Allow,

        # Removes all non-inherited permissions on the item.
        [switch] $Clear,

        # Returns an object representing the permission created or set on the `Path`. The returned object will have a
        # `Path` propery added to it so it can be piped to any cmdlet that uses a path.
        [switch] $PassThru,

        # Grants permissions, even if they are already present.
        [switch] $Force,

        # When granting permissions on files, directories, or registry items, add the permissions as a new access rule
        # instead of replacing any existing access rules.
        [switch] $Append,

        # ***Internal.*** Do not use.
        [String] $Description
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if (-not $ApplyTo)
    {
        $ApplyTo = 'ContainerSubcontainersAndLeaves'
    }

    $rArgs = Resolve-Arg -Path $Path `
                         -Identity $Identity `
                         -Permission $Permission `
                         -ApplyTo $ApplyTo `
                         -OnlyApplyToChildren:$OnlyApplyToChildren `
                         -Action 'grant'
    if (-not $rArgs)
    {
        return
    }

    $providerName = $rArgs.ProviderName
    $rights = $rArgs.Rights
    $accountName = $rArgs.AccountName
    $inheritanceFlags = $rArgs.InheritanceFlags
    $propagationFlags = $rArgs.PropagationFlags

    foreach ($currentPath in $rArgs.Paths)
    {
        # We don't use Get-Acl because it returns the whole security descriptor, which includes owner information. When
        # passed to Set-Acl, this causes intermittent errors.  So, we just grab the ACL portion of the security
        # descriptor. See
        # http://www.bilalaslam.com/2010/12/14/powershell-workaround-for-the-security-identifier-is-not-allowed-to-be-the-owner-of-this-object-with-set-acl/
        $currentAcl = Get-Item -LiteralPath $currentPath -Force | Get-CAcl -IncludeSection ([AccessControlSections]::Access)

        $testPermsFlagsArgs = @{ }
        if (Test-Path -LiteralPath $currentPath -PathType Container)
        {
            $testPermsFlagsArgs['ApplyTo'] = $ApplyTo
            $testPermsFlagsArgs['OnlyApplyToChildren'] = $OnlyApplyToChildren
        }
        else
        {
            $inheritanceFlags = [InheritanceFlags]::None
            $propagationFlags = [PropagationFlags]::None
            if($PSBoundParameters.ContainsKey('ApplyTo') -or $PSBoundParameters.ContainsKey('OnlyApplyToChildren'))
            {
                $msg = "Failed to set ""applies to"" flags on path ""${currentPath}"" because it is a file. Please " +
                       'omit "ApplyTo" and "OnlyApplyToChildren" parameters when granting permissions on a file.'
                Write-Warning $msg
            }
        }

        if (-not $Description)
        {
            $Description = $currentPath
        }

        $rulesToRemove = $null
        if( $Clear )
        {
            $rulesToRemove =
                $currentAcl.Access |
                Where-Object { $_.IdentityReference.Value -ne $accountName } |
                # Don't remove Administrators access.
                Where-Object { $_.IdentityReference.Value -ne 'BUILTIN\Administrators' } |
                Where-Object { -not $_.IsInherited }

            if( $rulesToRemove )
            {
                foreach( $ruleToRemove in $rulesToRemove )
                {
                    $rmType = $ruleToRemove.AccessControlType.ToString().ToLowerInvariant()
                    $rmRights = $ruleToRemove."${providerName}Rights"
                    Write-Information "${Description}  ${Identity}  - ${rmType} ${rmRights}"
                    [void]$currentAcl.RemoveAccessRule( $ruleToRemove )
                }
            }
        }


        $accessRule =
            New-Object -TypeName "Security.AccessControl.${providerName}AccessRule" `
                       -ArgumentList $accountName,$rights,$inheritanceFlags,$propagationFlags,$Type |
            Add-Member -MemberType NoteProperty -Name 'Path' -Value $currentPath -PassThru

        $missingPermission = -not (Test-CPermission -Path $currentPath `
                                                    -Identity $accountName `
                                                    -Permission $Permission `
                                                    @testPermsFlagsArgs `
                                                    -Strict)

        $setAccessRule = ($Force -or $missingPermission)
        if( $setAccessRule )
        {
            if( $Append )
            {
                $currentAcl.AddAccessRule( $accessRule )
            }
            else
            {
                $currentAcl.SetAccessRule( $accessRule )
            }
        }

        if ($rulesToRemove -or $setAccessRule)
        {
            $currentPerm = Get-CPermission -Path $currentPath -Identity $accountName
            $curRights = 0
            $curType = ''
            $curIdentity = $accountName
            if ($currentPerm)
            {
                $curType = $currentPerm.AccessControlType.ToString().ToLowerInvariant()
                $curRights = $currentPerm."${providerName}Rights"
                $curIdentity = $currentPerm.IdentityReference
            }
            $newType = $accessRule.AccessControlType.ToString().ToLowerInvariant()
            $newRights = $accessRule."${providerName}Rights"
            $newIdentity = $accessRule.IdentityReference
            if ($Append)
            {
                Write-Information "${Description}  ${newIdentity}  + ${newType} ${newRights}"
            }
            else
            {
                if ($currentPerm)
                {
                    Write-Information "${Description}  ${curIdentity}  - ${curType} ${curRights}"
                }
                Write-Information "${Description}  ${newIdentity}  + ${newType} ${newRights}"
            }
            Set-Acl -Path $currentPath -AclObject $currentAcl
        }

        if( $PassThru )
        {
            $accessRule | Write-Output
        }
    }
}
