

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