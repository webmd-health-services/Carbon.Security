
function Invoke-ConvertToCProviderAccessControlRights
{
    [CmdletBinding()]
    param(
        $ProviderName,
        $Permission
    )

    InModuleScope 'Carbon.Permissions' -ScriptBlock {
        param(
            $ProviderName,
            $Permission
        )
        $Permission | ConvertTo-CProviderAccessControlRights -ProviderName $ProviderName
    } -Parameters $PSBoundParameters
}

function Invoke-ConvertToCInheritanceFlag
{
    [CmdletBinding()]
    param(
        $ContainerInheritanceFlag
    )

    InModuleScope 'Carbon.Permissions' -ScriptBlock {
        param(
            $ContainerInheritanceFlag
        )
        ConvertTo-CInheritanceFlag -ContainerInheritanceFlag $ContainerInheritanceFlag
    } -Parameters $PSBoundParameters
}

function Invoke-ConvertToCPropagationFlag
{
    [CmdletBinding()]
    param(
        $ContainerInheritanceFlag
    )

    InModuleScope 'Carbon.Permissions' -ScriptBlock {
        param(
            $ContainerInheritanceFlag
        )
        ConvertTo-CPropagationFlag -ContainerInheritanceFlag $ContainerInheritanceFlag
    } -Parameters $PSBoundParameters
}

function Invoke-TestCCryptoKeyAvailable
{
    [CmdletBinding()]
    param(
    )

    InModuleScope 'Carbon.Permissions' -ScriptBlock {
        param(
        )
        Test-CCryptoKeyAvailable
    } -Parameters $PSBoundParameters
}