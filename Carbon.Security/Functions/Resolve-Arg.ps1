
function Resolve-Arg
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String] $Path,

        [String] $Identity,

        [String[]] $Permission,

        [String] $ApplyTo,

        [switch] $OnlyApplyToChildren,

        [Parameter(Mandatory)]
        [ValidateSet('get', 'grant', 'revoke', 'test')]
        [String] $Action
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $result = [pscustomobject]@{
        Paths = @();
        AccountName = '';
        Rights = 0x0;
        ProviderName = '';
        InheritanceFlags = [InheritanceFlags]::None;
        PropagationFlags = [PropagationFlags]::None;
    }

    $permsMsg = ' permissions'
    if ($Permission)
    {
        $permsMsg = " $($Permission -join ',') permissions"
    }

    $accountMsg = ''
    if ($Identity)
    {
        if (-not (Test-CIdentity -Name $Identity))
        {
            $msg = "Failed to ${Action}${permsMsg} on path ""${Path}"" to account ""${Identity}"" because that " +
                   'account does not exist.'
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }

        $accountName = $result.AccountName = Resolve-CIdentityName -Name $Identity
        $accountMsg = " account ""${accountName}"""

        if ($Permission)
        {
            $accountMsg = " ""${accountName}"" account's"
        }
    }

    if (-not (Test-Path -Path $Path))
    {
        $msg = "Failed to ${Action}${accountMsg}${permsMsg} on path ""${Path}"" because that path does not exist."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return $false
    }

    $result.Paths = $Path | Resolve-Path

    $providerName = Get-CPathProvider -Path $Path | Select-Object -ExpandProperty 'Name'
    if (-not $providerName)
    {
        $msg = "Failed to ${Action}${accountMsg}${permsMsg} on path ""${Path}"" because that path has an unknown " +
               'provider.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    if ($providerName -ne 'Registry' -and $providerName -ne 'FileSystem')
    {
        $msg = "Failed to ${Action}${accountMsg}${permsMsg} on path ""${Path}"" because that path uses the " +
               "unsupported ""${providerName}"" provider but only file system and registry paths are supported."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }
    $result.ProviderName = $providerName

    if ($Permission)
    {
        $rightTypeName = "Security.AccessControl.${providerName}Rights"

        $rights = 0 -as $rightTypeName

        foreach ($value in $Permission)
        {
            $right = $value -as $rightTypeName
            if (-not $right)
            {
                $allowedValues = [Enum]::GetNames($rightTypeName) -join ', '
                $msg = "Failed to ${Action}${accountMsg} ""${value}"" permission because that permission is invalid " +
                       "or unknown. It must be a [${rightTypeName}] enumeration value: ${allowedValues}."
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }

            Write-Debug "    ${value} → ${right}/0x$($right.ToString('x'))"
            $rights = $rights -bor $right
        }

        $result.Rights = $rights
    }

    if ($ApplyTo)
    {
        # ApplyTo                          OnlyApplyToChildren  InheritanceFlags                 PropagationFlags
        # -------                          -------------------  ----------------                 ----------------
        # ContainerOnly                    true                 None                             None
        # ContainerSubcontainersAndLeaves  true                 ContainerInherit, ObjectInherit  NoPropagateInherit
        # ContainerAndSubcontainers        true                 ContainerInherit                 NoPropagateInherit
        # ContainerAndLeaves               true                 ObjectInherit                    NoPropagateInherit
        # SubcontainersAndLeavesOnly       true                 ContainerInherit, ObjectInherit  NoPropagateInherit, InheritOnly
        # SubcontainersOnly                true                 ContainerInherit                 NoPropagateInherit, InheritOnly
        # LeavesOnly                       true                 ObjectInherit                    NoPropagateInherit, InheritOnly
        # ContainerOnly                    false                None                             None
        # ContainerSubcontainersAndLeaves  false                ContainerInherit, ObjectInherit  None
        # ContainerAndSubcontainers        false                ContainerInherit                 None
        # ContainerAndLeaves               false                ObjectInherit                    None
        # SubcontainersAndLeavesOnly       false                ContainerInherit, ObjectInherit  InheritOnly
        # SubcontainersOnly                false                ContainerInherit                 InheritOnly
        # LeavesOnly                       false                ObjectInherit                    InheritOnly

        $inheritanceFlags = [InheritanceFlags]::None
        $propagationFlags = [PropagationFlags]::None

        switch ($ApplyTo)
        {
            'ContainerOnly'
            {
                $inheritanceFlags = [InheritanceFlags]::None
                $propagationFlags = [PropagationFlags]::None
            }
            'ContainerSubcontainersAndLeaves'
            {
                $inheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit
                $propagationFlags = [PropagationFlags]::None
            }
            'ContainerAndSubcontainers'
            {
                $inheritanceFlags = [InheritanceFlags]::ContainerInherit
                $propagationFlags = [PropagationFlags]::None
            }
            'ContainerAndLeaves'
            {
                $inheritanceFlags = [InheritanceFlags]::ObjectInherit
                $propagationFlags = [PropagationFlags]::None
            }
            'SubcontainersAndLeavesOnly'
            {
                $inheritanceFlags = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit
                $propagationFlags = [PropagationFlags]::InheritOnly
            }
            'SubcontainersOnly'
            {
                $inheritanceFlags = [InheritanceFlags]::ContainerInherit
                $propagationFlags = [PropagationFlags]::InheritOnly
            }
            'LeavesOnly'
            {
                $inheritanceFlags = [InheritanceFlags]::ObjectInherit
                $propagationFlags = [PropagationFlags]::InheritOnly
            }
            default
            {
                $msg = "Failed to ${Action}${accountMsg}${permsMsg} on path ""${Path}"" because the ""AppliesTo"" " +
                       "parameter ""${ApplyTo}"" is invalid or unknown. Supported values are ""ContainerOnly, " +
                       'ContainerSubcontainersAndLeaves, ContainerAndSubcontainers, ContainerAndLeaves, ' +
                       'SubcontainersAndLeavesOnly, SubcontainersOnly, LeavesOnly"".'
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }
        }

        if ($OnlyApplyToChildren -and $ApplyTo -ne 'ContainerOnly')
        {
            $propagationFlags = $propagationFlags -bor [PropagationFlags]::NoPropagateInherit
        }

        $result.InheritanceFlags = $inheritanceFlags
        $result.PropagationFlags = $propagationFlags
    }

    return $result
}