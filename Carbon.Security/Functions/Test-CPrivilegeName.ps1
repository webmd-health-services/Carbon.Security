
function Test-CPrivilegeName
{
    <#
    .SYNOPSIS
    Tests if a right/privilege name is valid.

    .DESCRIPTION
    The `Test-CPrivilegeName` tests if a right/privilege name is valid or not. Not all privileges are supported on all
    operating systems. Use this function to test which privileges are valid or not. Pass the name to test to the `Name`
    parameter. The function returns `$true` if the rights/privilege name is valid, `$false` otherwise.

    Privilege names are validated using Windows APIs. There is no Windows API for account rights, so they are validated
    against [a list of known rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants).

    .EXAMPLE
    Test-CPrivilegeName -Name 'SeBatchLogonRight'

    Demonstrates how to use this function.
    #>
    [CmdletBinding()]
    param(
        # The right/privilege name to test.
        [Parameter(Mandatory, ValueFromPipeline)]
        [String] $Name,

        # Return the right/privilege's canonical name instead of `$true`.
        [switch] $PassThru
    )

    begin
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        $knownAccountRights = @(
            'SeBatchLogonRight',
            'SeDenyBatchLogonRight',
            'SeDenyInteractiveLogonRight',
            'SeDenyNetworkLogonRight',
            'SeDenyRemoteInteractiveLogonRight',
            'SeDenyServiceLogonRight',
            'SeInteractiveLogonRight',
            'SeNetworkLogonRight',
            'SeRemoteInteractiveLogonRight',
            'SeServiceLogonRight'
        )
    }

    process
    {
        $accountRight = $knownAccountRights | Where-Object { $_ -eq $Name }
        if ($accountRight)
        {
            if ($PassThru)
            {
                return $accountRight
            }
            return $true
        }

        $luid = Invoke-AdvApiLookupPrivilegeValue -Name $Name -ErrorAction Ignore
        if ($luid)
        {
            if ($PassThru)
            {
                return Invoke-AdvApiLookupPrivilegeName -LUID $luid
            }
            return $true
        }

        return $false
    }
}