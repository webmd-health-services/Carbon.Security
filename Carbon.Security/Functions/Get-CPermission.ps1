
function Get-CPermission
{
    <#
    .SYNOPSIS
    Gets the permissions (access control rules) for a file, directory, or registry key.

    .DESCRIPTION
    The `Get-CPermission` function gets the permissions, as access control rule objects, for a file, directory, or
    registry key. Using this function and module are not recommended. Instead,

    * for file directory permissions, use `Get-CNtfsPermission` in the `Carbon.FileSystem` module.
    * for registry permissions, use `Get-CRegistryPermission` in the `Carbon.Registry` module.
    * for private key and/or key container permissions, use `Get-CPrivateKeyPermission` in the `Carbon.Cryptography`
      module.

    Pass the path to the `Path` parameter. By default, all non-inherited permissions on that item are returned. To
    return inherited permissions, use the `Inherited` switch.

    To return the permissions for a specific user or group, pass the account's name to the `Identity` parameter.

    .OUTPUTS
    System.Security.AccessControl.AccessRule.

    .LINK
    Get-CPermission

    .LINK
    Grant-CPermission

    .LINK
    Revoke-CPermission

    .LINK
    Test-CPermission

    .EXAMPLE
    Get-CPermission -Path 'C:\Windows'

    Returns `System.Security.AccessControl.FileSystemAccessRule` objects for all the non-inherited rules on
    `C:\windows`.

    .EXAMPLE
    Get-CPermission -Path 'hklm:\Software' -Inherited

    Returns `System.Security.AccessControl.RegistryAccessRule` objects for all the inherited and non-inherited rules on
    `hklm:\software`.

    .EXAMPLE
    Get-CPermission -Path 'C:\Windows' -Idenity Administrators

    Returns `System.Security.AccessControl.FileSystemAccessRule` objects for all the `Administrators'` rules on
    `C:\windows`.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AccessRule])]
    param(
        # The path whose permissions (i.e. access control rules) to return. File system or registry paths supported.
        # Wildcards supported.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user/group name whose permissiosn (i.e. access control rules) to return.
        [String] $Identity,

        # Return inherited permissions in addition to explicit permissions.
        [switch] $Inherited
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $rArgs = Resolve-Arg -Path $Path -Identity $Identity -Action 'get'
    if (-not $rArgs)
    {
        return
    }

    Get-Item -Path $Path -Force |
        Get-CAcl -IncludeSection ([AccessControlSections]::Access) |
        Select-Object -ExpandProperty 'Access' |
        Where-Object {
            if ($Inherited)
            {
                return $true
            }
            return (-not $_.IsInherited)
        } |
        Where-Object {
            if ($Identity)
            {
                return ($_.IdentityReference.Value -eq $rArgs.AccountName)
            }

            return $true
        }
}
