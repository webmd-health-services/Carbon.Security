
function Get-CPrivilege
{
    <#
    .SYNOPSIS
    Gets an account's rights and privileges.

    .DESCRIPTION
    The `Get-CPrivilege` function gets an account's rights and privileges. These privileges are usually managed by Group
    Policy and control the system operations and types of logons an account can perform.

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
