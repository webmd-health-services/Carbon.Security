 function Grant-CPermission
{
    <#
    .SYNOPSIS
    Grants permission on a file, directory, registry key, or certificate's private key/key container.

    .DESCRIPTION
    The `Grant-CPermission` function grants permissions to files, directories, registry keys, and certificate private
    key/key containers. Using this function and module are not recommended. Instead,

    * for file directory permissions, use `Grant-CNtfsPermission` in the `Carbon.FileSystem` module.
    * for registry permissions, use `Grant-CRegistryPermission` in the `Carbon.Registry` module.
    * for private key and/or key container permissions, use `Grant-CPrivateKeyPermission` in the `Carbon.Cryptography`
      module.

    Pass the item's path to the `Path` parameter, the name of the identity receiving the permission to the `Identity`
    parameter, and the permission to grant to the `Permission` parameter. If the identity doesn't have the permission,
    the item's ACL is updated to include the new permission. If the identity has permission, but it doesn't match the
    permission being set, the user's current permissions are changed to match. If the user already has the given
    permission, nothing happens. Inherited permissions are ignored. To always grant permissions, use the `Force`
    (switch).

    The `Permissions` attribute should be a list of
    [FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx),
    [RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx), or
    [CryptoKeyRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx), for
    files/directories, registry keys, and certificate private keys, respectively. These commands will show you the
    values for the appropriate permissions for your object:

        [Enum]::GetValues([Security.AccessControl.FileSystemRights])
        [Enum]::GetValues([Security.AccessControl.RegistryRights])
        [Enum]::GetValues([Security.AccessControl.CryptoKeyRights])

    To get back the access rule, use the `PassThru` switch.

    By default, an `Allow` access rule is created and granted. To create a `Deny` access rule, pass `Deny` to the `Type`
    parameter.

    To append/add permissions instead or replacing existing permissions on use the `Append` switch.

    To control how the permission is applied and inherited to child items, use the `InheritanceFlag` and
    `PropagationFlag` parameters to set the permission's inheritance and propagation flags, respectively. See [Manage
    Access to Windows Objects with ACLs and the .NET
    Framework](https://learn.microsoft.com/en-us/archive/msdn-magazine/2004/november/manage-access-to-windows-objects-with-acls-and-the-net-framework#S3)
    from the November 2004 issue of *MSDN Magazine*.

    To remove all other non-inherited permissions from the item, use the `Clear` switch. When using the `-Clear` switch
    and setting permissions on a private key in Windows PowerShell and the key is not a crypograhic next generation key,
    the local `Administrators` account will always remain. In testing on Windows 2012 R2, we noticed that when
    `Administrators` access was removed, you couldn't read the key anymore.

    .OUTPUTS
    System.Security.AccessControl.AccessRule. When setting permissions on a file or directory, a
    `System.Security.AccessControl.FileSystemAccessRule` is returned. When setting permissions on a registry key, a
    `System.Security.AccessControl.RegistryAccessRule` returned. When setting permissions on a private key, a
    `System.Security.AccessControl.CryptoKeyAccessRule` object is returned.

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
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx

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
    Grant-CPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Grants the Enterprise's engineering group full control on the `1234567890ABCDEF1234567890ABCDEF12345678`
    certificate's private key/key container.

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
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Security.AccessControl.AccessRule])]
    param(
        # The path on which the permissions should be granted.  Can be a file system, registry, or certificate path.If
        # the path is relative, it uses the current location to determine the full path. For certificate private keys,
        # pass a certificate provider path, e.g. `cert:`.
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

        # The inheritance flags for the permission. Default is `ContainerInherit` and `ObjectInherit`. See [Manage
        # Access to Windows Objects with ACLs and the .NET
        # Framework](https://learn.microsoft.com/en-us/archive/msdn-magazine/2004/november/manage-access-to-windows-objects-with-acls-and-the-net-framework#S3)
        # from the November 2004 issue of *MSDN Magazine* for more information.
        [InheritanceFlags] $InheritanceFlag =
            ([InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit),

        # The propagation flags for the permission. Default is `None`.  See [Manage Access to Windows Objects with ACLs
        # and the .NET
        # Framework](https://learn.microsoft.com/en-us/archive/msdn-magazine/2004/november/manage-access-to-windows-objects-with-acls-and-the-net-framework#S3)
        # from the November 2004 issue of *MSDN Magazine* for more information.
        [PropagationFlags] $PropagationFlag = [PropagationFlags]::None,

        # The type of rule to apply, either `Allow` or `Deny`. The default is `Allow`, which will allow access to the
        # item. The other option is `Deny`, which will deny access to the item.
        [AccessControlType] $Type = [AccessControlType]::Allow,

        # Removes all non-inherited permissions on the item.
        #
        # If this is set and `Path` is to a non-cryptographic next generation key, and runnning under Windows
        # PowerShell, Administrator permissions will never be removed.
        [switch] $Clear,

        # Returns an object representing the permission created or set on the `Path`. The returned object will have a
        # `Path` propery added to it so it can be piped to any cmdlet that uses a path.
        [switch] $PassThru,

        # Grants permissions, even if they are already present.
        [switch] $Force,

        # When granting permissions on files, directories, or registry items, add the permissions as a new access rule
        # instead of replacing any existing access rules. This switch is ignored when setting permissions on private
        # keys.
        [switch] $Append,

        # ***Internal.*** Do not use.
        [String] $Description
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $Path = Resolve-Path -Path $Path
    if( -not $Path )
    {
        return
    }

    $providerName = Get-CPathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    if( $providerName -eq 'Certificate' )
    {
        $providerName = 'CryptoKey'
    }

    if( $providerName -ne 'Registry' -and $providerName -ne 'FileSystem' -and $providerName -ne 'CryptoKey' )
    {
        Write-Error "Unsupported path: '$Path' belongs to the '$providerName' provider.  Only file system, registry, and certificate paths are supported."
        return
    }

    $rights = $Permission | ConvertTo-CProviderAccessControlRights -ProviderName $providerName
    if (-not $rights)
    {
        Write-Error ('Unable to grant {0} {1} permissions on {2}: received an unknown permission.' -f $Identity,($Permission -join ','),$Path)
        return
    }

    if( -not (Test-CPrincipal -Name $Identity) )
    {
        Write-Error ('Identity ''{0}'' not found.' -f $Identity)
        return
    }

    $Identity = Resolve-CPrincipalName -Name $Identity

    if ($providerName -eq 'CryptoKey')
    {
        foreach ($certificate in (Get-Item -Path $Path))
        {
            $certPath = Join-Path -Path 'cert:' -ChildPath ($certificate.PSPath | Split-Path -NoQualifier)
            $subject = $certificate.Subject
            $thumbprint = $certificate.Thumbprint
            if( -not $certificate.HasPrivateKey )
            {
                $msg = "Unable to grant permission to ${subject} (thumbprint: ${thumbprint}; path ${certPath}) " +
                       'certificate''s private key because that certificate doesn''t have a private key.'
                Write-Warning $msg
                return
            }

            if (-not $Description)
            {
                $Description = "${certPath} ${subject}"
            }

            if (-not $certificate.PrivateKey -or `
                -not ($certificate.PrivateKey | Get-Member -Name 'CspKeyContainerInfo'))
            {
                $privateKeyFilePaths = $certificate | Resolve-CPrivateKeyPath
                if( -not $privateKeyFilePaths )
                {
                    # Resolve-CPrivateKeyPath writes an appropriately detailed error message.
                    continue
                }

                $grantPermArgs = New-Object -TypeName 'Collections.Generic.Dictionary[[String], [Object]]' `
                                            -ArgumentList $PSBoundParameters
                [void]$grantPermArgs.Remove('Path')
                [void]$grantPermArgs.Remove('Permission')

                foreach ($privateKeyFile in $privateKeyFilePaths)
                {
                    Grant-CPermission -Path $privateKeyFile -Permission $rights @grantPermArgs -Description $Description
                }
                continue
            }

            [Security.AccessControl.CryptoKeySecurity]$keySecurity =
                $certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
            if (-not $keySecurity)
            {
                $msg = "Failed to grant permission to ${subject} (thumbprint: ${thumbprint}; path: ${certPath}) " +
                       'certificate''s private key because the private key has no security information.'
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                continue
            }

            $rulesToRemove = @()
            if ($Clear)
            {
                $rulesToRemove =
                    $keySecurity.Access |
                    Where-Object { $_.IdentityReference.Value -ne $Identity } |
                    # Don't remove Administrators access.
                    Where-Object { $_.IdentityReference.Value -ne 'BUILTIN\Administrators' }
                if ($rulesToRemove)
                {
                    foreach ($ruleToRemove in $rulesToRemove)
                    {
                        $rmIdentity = $ruleToRemove.IdentityReference.ToString()
                        $rmType = $ruleToRemove.AccessControlType.ToString().ToLowerInvariant()
                        $rmRights = $ruleToRemove.CryptoKeyRights
                        Write-Information "${Description}  ${rmIdentity}  - ${rmType} ${rmRights}"
                        if (-not $keySecurity.RemoveAccessRule($ruleToRemove))
                        {
                            $msg = "Failed to remove ""${rmIdentity}"" identity's ${rmType} ""${rmRights}"" " +
                                   "permissions to ${subject} (thumbprint: ${thumbprint}; path: ${certPath}) " +
                                   'certificates''s private key.'
                            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                            continue
                        }
                    }
                }
            }

            $accessRule =
                New-Object -TypeName 'Security.AccessControl.CryptoKeyAccessRule' `
                           -ArgumentList $Identity, $rights, $Type |
                Add-Member -MemberType NoteProperty -Name 'Path' -Value $certPath -PassThru

            if ($Force -or `
                $rulesToRemove -or `
                -not (Test-CPermission -Path $certPath -Identity $Identity -Permission $Permission -Exact))
            {
                $currentPerm = Get-CPermission -Path $certPath -Identity $Identity
                if ($currentPerm)
                {
                    $curType = $currentPerm.AccessControlType.ToString().ToLowerInvariant()
                    $curRights = $currentPerm."$($providerName)Rights"
                    Write-Information "${Description}  ${Identity}  - ${curType} ${curRights}"
                }
                $newType = $Type.ToString().ToLowerInvariant()
                Write-Information "${Description}  ${Identity}  + ${newType} ${rights}"
                $keySecurity.SetAccessRule($accessRule)
                $action = "grant ""${Identity} ${newType} ${rights} permission(s)"
                Set-CCryptoKeySecurity -Certificate $certificate -CryptoKeySecurity $keySecurity -Action $action
            }

            if( $PassThru )
            {
                return $accessRule
            }
        }
        return
    }

    # We don't use Get-Acl because it returns the whole security descriptor, which includes owner information. When
    # passed to Set-Acl, this causes intermittent errors.  So, we just grab the ACL portion of the security
    # descriptor. See
    # http://www.bilalaslam.com/2010/12/14/powershell-workaround-for-the-security-identifier-is-not-allowed-to-be-the-owner-of-this-object-with-set-acl/
    $currentAcl = (Get-Item -Path $Path -Force).GetAccessControl([Security.AccessControl.AccessControlSections]::Access)

    $testPermissionParams = @{ }
    if (Test-Path $Path -PathType Container)
    {
        $testPermissionParams['InheritanceFlag'] = $InheritanceFlag
        $testPermissionParams['PropagationFlag'] = $PropagationFlag
    }
    else
    {
        $InheritanceFlag = [InheritanceFlags]::None
        $PropagationFlag = [PropagationFlags]::None
        if($PSBoundParameters.ContainsKey('InheritanceFlag') -or $PSBoundParameters.ContainsKey('PropagationFlag'))
        {
            $msg = 'Can''t apply inheritance/propagation flags to a leaf. Please omit "InheritanceFlag" and ' +
                   '"PropagationFlag" parameters when `Path` is a leaf.'
            Write-Warning $msg
        }
    }

    if (-not $Description)
    {
        $Description = $Path
    }

    $rulesToRemove = $null
    $Identity = Resolve-CPrincipalName -Name $Identity
    if( $Clear )
    {
        $rulesToRemove = $currentAcl.Access |
                            Where-Object { $_.IdentityReference.Value -ne $Identity } |
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
        New-Object -TypeName "Security.AccessControl.$($providerName)AccessRule" `
                   -ArgumentList $Identity,$rights,$InheritanceFlag,$PropagationFlag,$Type |
        Add-Member -MemberType NoteProperty -Name 'Path' -Value $Path -PassThru

    $missingPermission =
        -not (Test-CPermission -Path $Path -Identity $Identity -Permission $Permission @testPermissionParams -Exact)

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
        $currentPerm = Get-CPermission -Path $Path -Identity $Identity
        $curRights = 0
        $curType = ''
        $curIdentity = $Identity
        if ($currentPerm)
        {
            $curType = $currentPerm.AccessControlType.ToString().ToLowerInvariant()
            $curRights = $currentPerm."$($providerName)Rights"
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
        Set-Acl -Path $Path -AclObject $currentAcl
    }

    if( $PassThru )
    {
        return $accessRule
    }
}
