
function Grant-CPrivilege
{
    <#
    .SYNOPSIS
    Grants an account privileges to perform system operations.

    .DESCRIPTION
    The `Grant-CPrivilege` function grants a user/group rights and privileges. Pass the name of the user/group to the
    `Identity` parameter. Pass the list of account rights and/or privileges to grant to the `Privilege` parameter. The
    account is granted any rights/privileges it doesn't currently have.

    Rights and privilege names are documented on Microsoft's website, duplicated below. These lists may be out-of-date.

    [Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants):

     * SeAssignPrimaryTokenPrivilege
     * SeAuditPrivilege
     * SeBackupPrivilege
     * SeChangeNotifyPrivilege
     * SeCreateGlobalPrivilege
     * SeCreatePagefilePrivilege
     * SeCreatePermanentPrivilege
     * SeCreateSymbolicLinkPrivilege
     * SeCreateTokenPrivilege
     * SeDebugPrivilege
     * SeDelegateSessionUserImpersonatePrivilege
     * SeEnableDelegationPrivilege
     * SeImpersonatePrivilege
     * SeIncreaseBasePriorityPrivilege
     * SeIncreaseQuotaPrivilege
     * SeIncreaseWorkingSetPrivilege
     * SeLoadDriverPrivilege
     * SeLockMemoryPrivilege
     * SeMachineAccountPrivilege
     * SeManageVolumePrivilege
     * SeProfileSingleProcessPrivilege
     * SeRelabelPrivilege
     * SeRemoteInteractiveLogonRight
     * SeRemoteShutdownPrivilege
     * SeRestorePrivilege
     * SeSecurityPrivilege
     * SeShutdownPrivilege
     * SeSyncAgentPrivilege
     * SeSystemEnvironmentPrivilege
     * SeSystemProfilePrivilege
     * SeSystemtimePrivilege
     * SeTakeOwnershipPrivilege
     * SeTcbPrivilege
     * SeTimeZonePrivilege
     * SeTrustedCredManAccessPrivilege
     * SeUndockPrivilege
     * SeUnsolicitedInputPrivilege

    [Account Right Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants):

     * SeBatchLogonRight
     * SeDenyBatchLogonRight
     * SeDenyInteractiveLogonRight
     * SeDenyNetworkLogonRight
     * SeDenyRemoteInteractiveLogonRight
     * SeDenyServiceLogonRight
     * SeInteractiveLogonRight
     * SeNetworkLogonRight
     * SeServiceLogonRight

    .LINK
    Get-CPrivilege

    .LINK
    Revoke-CPrivilege

    .LINK
    Test-CPrivilege

    .LINK
    Test-CPrivilegeName

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants

    .EXAMPLE
    Grant-CPrivilege -Identity Batcomputer -Privilege SeServiceLogonRight

    Grants the Batcomputer account the ability to logon as a service.
    #>
    [CmdletBinding()]
    param(
        # The user/group name to grant rights/privileges.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The rights/privileges to grant.
        #
        # [Privilege names are documented on the "Privilege Constants"
        # page.](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
        #
        # [Rights names are documented on the "Account Rights Constants"
        # page.](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants)
        [Parameter(Mandatory)]
        [String[]] $Privilege
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $account = Resolve-CIdentity -Name $Identity
    if( -not $account )
    {
        return
    }

    $privilegesToGrant = $Privilege | Where-Object { -not (Test-CPrivilege -Identity $account.FullName -Privilege $_) }
    if (-not $privilegesToGrant)
    {
        return
    }

    $unknownPrivileges = $privilegesToGrant | Where-Object { -not (Test-CPrivilegeName -Name $_) }
    if ($unknownPrivileges)
    {
        $privileges = 'privilege'
        $thatThose = 'that'
        $isAre = 'is'
        if (($unknownPrivileges | Measure-Object).Count -gt 1)
        {
            $privileges = 'privileges'
            $thatThose = 'those'
            $isAre = 'are'
        }
        $msg = "Failed to grant the $($account.FullName) account $($unknownPrivileges -join ', ') ${privileges} " +
               "because ${thatThose} ${privileges} ${isAre} unknown."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
    }

    # Privilege names are case-sensitive when granting, so get the actual value of the privilege names.
    $privilegesToGrant = $privilegesToGrant | Test-CPrivilegeName -PassThru | Where-Object { $_ }
    if (-not $privilegesToGrant)
    {
        return
    }

    $pHandle = Invoke-AdvApiLsaOpenPolicy -DesiredAccess CreateAccount,LookupNames
    if (-not $pHandle)
    {
        return
    }

    try
    {
        Write-Information "$($account.FullName)  + $($privilegesToGrant -join ',')"
        Invoke-AdvApiLsaAddAccountRights -PolicyHandle $pHandle -Sid $account.Sid -Privilege $privilegesToGrant |
            Out-Null
    }
    finally
    {
        Invoke-AdvApiLsaClose -PolicyHandle $pHandle | Out-Null
    }
}
