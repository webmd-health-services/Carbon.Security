
function Revoke-CPermission
{
    <#
    .SYNOPSIS
    Revokes permissions on a file, directory, or registry keys.

    .DESCRIPTION
    The `Revoke-CPermission` function removes a user or group's *explicit, non-inherited* permissions on a file,
    directory, or registry key. Using this function and module are not recommended. Instead,

    * for file directory permissions, use `Revoke-CNtfsPermission` in the `Carbon.FileSystem` module.
    * for registry permissions, use `Revoke-CRegistryPermission` in the `Carbon.Registry` module.
    * for private key and/or key container permissions, use `Revoke-CPrivateKeyPermission` in the `Carbon.Cryptography`
      module.

    Pass the path to the item to the `Path` parameter. Pass the user/group's name to the `Identity` parameter. If the
    identity has any non-inherited permissions on the item, those permissions are removed. If the identity has no
    permissions on the item, nothing happens.

    .LINK
    Get-CPermission

    .LINK
    Grant-CPermission

    .LINK
    Test-CPermission

    .EXAMPLE
    Revoke-CPermission -Identity ENTERPRISE\Engineers -Path 'C:\EngineRoom'

    Demonstrates how to revoke all of the 'Engineers' permissions on the `C:\EngineRoom` directory.

    .EXAMPLE
    Revoke-CPermission -Identity ENTERPRISE\Interns -Path 'hklm:\system\WarpDrive'

    Demonstrates how to revoke permission on a registry key.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSShouldProcess', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # The path on which the permissions should be revoked. Can be a file system or registry path.
        [Parameter(Mandatory)]
        [String] $Path,

        # The identity losing permissions.
        [Parameter(Mandatory)]
        [String] $Identity,

        # ***Internal.*** Do not use.
        [String] $Description
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $rArgs = Resolve-Arg -Path $Path -Identity $Identity -Action 'revoke'
    if (-not $rArgs)
    {
        return
    }

    $accountName = $rArgs.AccountName

    $rulesToRemove = Get-CPermission -Path $Path -Identity $accountName
    if (-not $rulesToRemove)
    {
        return
    }

    $providerName = $rArgs.ProviderName

    foreach ($currentPath in $rArgs.Paths)
    {
        if (-not $Description)
        {
            $Description = $currentPath
        }

        # We don't use Get-Acl because it returns the whole security descriptor, which includes owner information.
        # When passed to Set-Acl, this causes intermittent errors.  So, we just grab the ACL portion of the security
        # descriptor. See
        # http://www.bilalaslam.com/2010/12/14/powershell-workaround-for-the-security-identifier-is-not-allowed-to-be-the-owner-of-this-object-with-set-acl/
        $currentAcl =
            Get-Item -LiteralPath $currentPath -Force | Get-CAcl -IncludeSection ([AccessControlSections]::Access)

        foreach ($ruleToRemove in $rulesToRemove)
        {
            $rmIdentity = $ruleToRemove.IdentityReference
            $rmType = $ruleToRemove.AccessControlType.ToString().ToLowerInvariant()
            $rmRights = $ruleToRemove."${providerName}Rights"
            Write-Information "${Description}  ${rmIdentity}  - ${rmType} ${rmRights}"
            [void]$currentAcl.RemoveAccessRule($ruleToRemove)
        }

        if ($PSCmdlet.ShouldProcess($currentPath, "revoke ""${accountName}"" account's permissions"))
        {
            Set-Acl -Path $currentPath -AclObject $currentAcl
        }
    }
}

