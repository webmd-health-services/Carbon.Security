
function Get-CPrivilege
{
    <#
    .SYNOPSIS
    Gets an account's rights and privileges.

    .DESCRIPTION
    The `Get-CPrivilege` function gets an account's rights and privileges. These privileges are usually managed by Group
    Policy and control the system operations and types of logons an account can perform. Only privileges directly
    granted to the account are returned. If an account is granted a privilege through a group, those privileges are
    *not* returned.

    [Windows privileges can be in one of three states:](https://superuser.com/a/1254265/45274)

    * not granted
    * granted and enabled
    * granted and disabled

    The `Get-CPrivilege` function returns granted privileges, regardless if they are enabled or disabled.

    .OUTPUTS
    System.String

    .LINK
    Grant-CPrivilege

    .LINK
    Revoke-CPrivilege

    .LINK
    Test-CPrivilege

    .LINK
    Test-CPrivilegeName

    .EXAMPLE
    Get-CPrivilege -Identity TheBeast

    Gets `TheBeast` account's privileges as an array of strings.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        # The user/group name whose privileges to return.
        [Parameter(Mandatory)]
        [String] $Identity
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $account = Resolve-CPrincipal -Name $Identity
    if (-not $account)
    {
        return
    }

    $pHandle = Invoke-AdvApiLsaOpenPolicy -DesiredAccess LookupNames
    if (-not $pHandle)
    {
        return
    }

    try
    {
        Invoke-AdvApiLsaEnumerateAccountRights -PolicyHandle $pHandle -Sid $account.Sid | Write-Output
    }
    finally
    {
        Invoke-AdvApiLsaClose -PolicyHandle $pHandle | Out-Null
    }
}
