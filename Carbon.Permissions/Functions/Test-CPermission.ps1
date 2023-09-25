
function Test-CPermission
{
    <#
    .SYNOPSIS
    Tests permissions on a file, directory, registry key, or certificate private key/key container.

    .DESCRIPTION
    The `Test-CPermission` function tests if permissions are granted to a user or group on a file, directory, registry
    key, or certificate private key/key container. Using this function and module are not recommended. Instead,

    * for file directory permissions, use `Test-CNtfsPermission` in the `Carbon.FileSystem` module.
    * for registry permissions, use `Test-CRegistryPermission` in the `Carbon.Registry` module.
    * for private key and/or key container permissions, use `Test-CPrivateKeyPermission` in the `Carbon.Cryptography`
      module.

    Pass the path to the item to the `Path` parameter. Pass the user/group name to the `Identity` parameter. Pass the
    permissions to check for to the `Permission` parameter. If the user has all those permissions on that item, the
    function returns `true`. Otherwise it returns `false`.

    The `Permissions` attribute should be a list of
    [FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx),
    [RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx), or
    [CryptoKeyRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx), for
    files/directories, registry keys, and certificate private keys, respectively. These commands will show you the
    values for the appropriate permissions for your object:

        [Enum]::GetValues([Security.AccessControl.FileSystemRights])
        [Enum]::GetValues([Security.AccessControl.RegistryRights])
        [Enum]::GetValues([Security.AccessControl.CryptoKeyRights])

    Extra/additional permissions on the item are ignored. To check that the user/group has the exact permissions passed
    to the `Permission` parameter, use the `Strict` switch.

    You can also check that the item's inheritenche and propagation flags by using the InheritanceFlag and
     PropagationFlag parameters. Like the `Permissions` parameter, additional/extra flags are ignored. To ensure the
     exact inheritance and propagation flags that are passed are also on the item, use the `Strict` switch.

    By default, inherited permissions are ignored. To check inherited permission, use the `-Inherited` switch.

    .OUTPUTS
    System.Boolean.

    .LINK
    Get-CPermission

    .LINK
    Grant-CPermission

    .LINK
    Revoke-CPermission

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx

    .EXAMPLE
    Test-CPermission -Identity 'STARFLEET\JLPicard' -Permission 'FullControl' -Path 'C:\Enterprise\Bridge'

    Demonstrates how to check that Jean-Luc Picard has `FullControl` permission on the `C:\Enterprise\Bridge`.

    .EXAMPLE
    Test-CPermission -Identity 'STARFLEET\GLaForge' -Permission 'WriteKey' -Path 'HKLM:\Software\Enterprise\Engineering'

    Demonstrates how to check that Geordi LaForge can write registry keys at `HKLM:\Software\Enterprise\Engineering`.

    .EXAMPLE
    Test-CPermission -Identity 'STARFLEET\Worf' -Permission 'Write' -ApplyTo 'Container' -Path 'C:\Enterprise\Brig'

    Demonstrates how to test for inheritance/propogation flags, in addition to permissions.

    .EXAMPLE
    Test-CPermission -Identity 'STARFLEET\Data' -Permission 'GenericWrite' -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to test for permissions on a certificate's private key/key container. If the certificate doesn't
    have a private key, returns `$true`.
    #>
    [CmdletBinding()]
    param(
        # The path on which the permissions should be checked.  Can be a file system or registry path. For certificate
        # private keys, pass a certificate provider path, e.g. `cert:`.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user or group whose permissions to check.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The permission to test for: e.g. FullControl, Read, etc.  For file system items, use values from
        # [System.Security.AccessControl.FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx).
        # For registry items, use values from
        # [System.Security.AccessControl.RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx).
        [Parameter(Mandatory)]
        [String[]] $Permission,

        # The inheritance flags to check for. Default is to ignore inheritance flags when testing the permission.
        [InheritanceFlags] $InheritanceFlag,

        # The propagation flags to check for. Default is to ignore propagation flags when testing the permission.
        [PropagationFlags] $PropagationFlag,

        # Include inherited permissions in the check.
        [switch] $Inherited,

        # Check for the exact permissions, inheritance flags, and propagation flags, i.e. make sure the identity has
        # *only* the permissions you specify.
        [switch] $Strict
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $originalPath = $Path
    $Path = Resolve-Path -Path $Path -ErrorAction 'SilentlyContinue'
    if( -not $Path -or -not (Test-Path -Path $Path) )
    {
        if( -not $Path )
        {
            $Path = $originalPath
        }
        Write-Error ('Unable to test {0}''s {1} permissions: path ''{2}'' not found.' -f $Identity,($Permission -join ','),$Path)
        return
    }

    $providerName = Get-CPathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    if( $providerName -eq 'Certificate' )
    {
        $providerName = 'CryptoKey'
        # CryptoKey does not exist in .NET standard/core so we will have to use FileSystem instead
        if( -not (Test-CCryptoKeyAvailable) )
        {
            $providerName = 'FileSystem'
        }
    }

    if (($providerName -eq 'FileSystem' -or $providerName -eq 'CryptoKey') -and $Strict)
    {
        # Synchronize is always on and can't be turned off.
        $Permission += 'Synchronize'
    }
    $rights = $Permission | ConvertTo-CProviderAccessControlRights -ProviderName $providerName
    if( -not $rights )
    {
        Write-Error ('Unable to test {0}''s {1} permissions on {2}: received an unknown permission.' -f $Identity,$Permission,$Path)
        return
    }

    $rightsPropertyName = "${providerName}Rights"
    $isLeaf = (Test-Path -Path $Path -PathType Leaf)
    $testInheritanceFlag = $PSBoundParameters.ContainsKey('InheritanceFlag')
    $testPropagationFlag = $PSBoundParameters.ContainsKey('PropagationFlag')
    if ($isLeaf -and ($testInheritanceFlag -or $testPropagationFlag))
    {
        $InheritanceFlag = [InheritanceFlags]::None
        $PropagationFlag = [PropagationFlags]::None
        $msg = 'Can''t test inheritance/propagation rules on a leaf. Please omit `InheritanceFlag` and ' +
                '`PropagationFlag` parameter when `Path` is a leaf.'
        Write-Warning $msg
    }

    if( $providerName -eq 'CryptoKey' )
    {
        # If the certificate doesn't have a private key, return $true.
        if( (Get-Item -Path $Path | Where-Object { -not $_.HasPrivateKey } ) )
        {
            return $true
        }
    }


    $acl =
        Get-CPermission -Path $Path -Identity $Identity -Inherited:$Inherited |
        Where-Object 'AccessControlType' -eq 'Allow' |
        Where-Object 'IsInherited' -eq $Inherited |
        Where-Object {
            if ($Strict)
            {
                return ($_.$rightsPropertyName -eq $rights)
            }

            return ($_.$rightsPropertyName -band $rights) -eq $rights
        } |
        Where-Object {
            if ($isLeaf)
            {
                return $true
            }

            if (-not $testInheritanceFlag)
            {
                return $true
            }

            if ($Strict)
            {
                return ($_.InheritanceFlags -eq $InheritanceFlag)
            }

            return (($_.InheritanceFlags -band $InheritanceFlag) -eq $InheritanceFlag)
        } |
        Where-Object {
            if ($isLeaf)
            {
                return $true
            }

            if (-not $testPropagationFlag)
            {
                return $true
            }

            if ($Strict)
            {
                return ($_.PropagationFlags -eq $PropagationFlag)
            }

            return (($_.PropagationFlags -band $PropagationFlag) -eq $PropagationFlag)
        }

    if ($acl)
    {
        return $true
    }

    return $false
}

