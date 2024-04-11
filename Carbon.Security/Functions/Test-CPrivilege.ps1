
function Test-CPrivilege
{
    <#
    .SYNOPSIS
    Tests if an identity has a given privilege.

    .DESCRIPTION
    Returns `true` if an identity has a privilege.  `False` otherwise.

    .LINK
    Carbon_Privilege

    .LINK
    Get-CPrivilege

    .LINK
    Grant-CPrivilege

    .LINK
    Revoke-CPrivilege

    .LINK
    Test-CPrivilegeName

    .EXAMPLE
    Test-CPrivilege -Identity Forrester -Privilege SeServiceLogonRight

    Tests if `Forrester` has the `SeServiceLogonRight` privilege.
    #>
    [CmdletBinding()]
    param(
        # The identity whose privileges to check.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The privilege to check.
        [Parameter(Mandatory)]
        [String] $Privilege
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $matchingPrivilege = Get-CPrivilege -Identity $Identity | Where-Object { $_ -eq $Privilege }
    return ($null -ne $matchingPrivilege)
}

