
function Set-CAcl
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Object] $InputObject,

        [Object] $AclObject
    )

    process
    {
        # When replacing the current user's permissions on a file or directory that doesn't inherit ACL permissions, the
        # Set-Acl cmdlet fails with "The process does not possess the 'SeSecurityPrivilege' privilege which is required
        # for this operation." error, so use SetAccessControl directly when possible.
        #
        # SetAccessControl fails when attempting to change permissions on HKCU, even though user has permissions.
        if ($InputObject -is [IO.FileSystemInfo])
        {
            if ($InputObject | Get-Member -Name 'SetAccessControl')
            {
                $InputObject.SetAccessControl($acl)
                return
            }

            [IO.FileSystemAclExtensions]::SetAccessControl($InputObject, $AclObject)
            return
        }

        Set-Acl -Path $InputObject.PSPath -AclObject $AclObject
    }
}