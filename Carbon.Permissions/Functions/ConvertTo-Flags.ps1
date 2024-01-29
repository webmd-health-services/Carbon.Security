
function ConvertTo-Flags
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ContainerOnly', 'ContainerSubcontainersAndLeaves', 'ContainerAndSubcontainers',
            'ContainerAndLeaves', 'SubcontainersAndLeavesOnly', 'SubcontainersOnly', 'LeavesOnly')]
        [String] $ApplyTo,

        [switch] $OnlyApplyToChildren
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

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
    }

    if ($OnlyApplyToChildren -and $ApplyTo -ne 'ContainerOnly')
    {
        $propagationFlags = $propagationFlags -bor [PropagationFlags]::NoPropagateInherit
    }

    return [pscustomobject]@{
        InheritanceFlags = $inheritanceFlags;
        PropagationFlags = $propagationFlags;
    }
}