
function Revoke-CPrivilege
{
    <#
    .SYNOPSIS
    Removes an account's rights and/or privileges.

    .DESCRIPTION
    The `Revoke-CPrivilege` function removes a user or group's rights and/or privileges. Pass the user/group name to the
    `Identity` parameter. Pass the right/privilege names to remove to the `Privilege` parameter. Any right/privilege the
    user/group has is removed. If the user doesn't have the right/privilege, nothing happens.

    To see the user/group's current rights/privileges, use the `Get-CPrivilege` function.

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
    Grant-CPrivilege

    .LINK
    Test-CPrivilege

    .LINK
    Test-CPrivilegeName

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants

    .EXAMPLE
    Revoke-CPrivilege -Identity Batcomputer -Privilege SeServiceLogonRight

    Revokes the Batcomputer account's ability to logon as a service.  Don't restart that thing!
    #>
    [CmdletBinding()]
    param(
        # The identity to grant a privilege.
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

    $unknownPrivileges = $Privilege | Where-Object { -not (Test-CPrivilegeName -Name $_) }
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
        $msg = "Failed to revoke the $($account.FullName) account's $($unknownPrivileges -join ', ') ${privileges} " +
               "because ${thatThose} ${privileges} ${isAre} unknown."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
    }

    $privilegesToRevoke = $Privilege | Where-Object { (Test-CPrivilege -Identity $account.FullName -Privilege $_) }
    if (-not $privilegesToRevoke)
    {
        return
    }

    # Privilege names are case-sensitive when granting, so get the actual value of the privilege names.
    $privilegesToRevoke = $privilegesToRevoke | Test-CPrivilegeName -PassThru | Where-Object { $_ }
    if (-not $privilegesToRevoke)
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
        Write-Information "$($account.FullName)  - $($privilegesToRevoke -join ',')"
        Invoke-AdvApiLsaRemoveAccountRights -PolicyHandle $pHandle -Sid $account.Sid -Privilege $privilegesToRevoke |
            Out-Null
    }
    finally
    {
        Invoke-AdvApiLsaClose -PolicyHandle $pHandle | Out-Null
    }
}

