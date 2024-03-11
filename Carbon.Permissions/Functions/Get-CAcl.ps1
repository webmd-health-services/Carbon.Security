
function Get-CAcl
{
    <#
    .SYNOPSIS
    Gets the access control (i.e. security descriptor) for a file, directory, or registry key.

    .DESCRIPTION
    The `Get-CAcl` function gets the access control (i.e. security descriptor) for a file, directory, or registry key.
    Pipe the item whose security descriptor to get to the function. By default all parts of the security descriptor
    information is returned. To return only specific sections of the security descriptor, pass the sections to get to
    the `IncludeSection` parameter.

    .EXAMPLE
    Get-Item . | Get-CAcl

    Demonstrates how to get the security descriptor for an item by piping it into `Get-CAcl`.

    .EXAMPLE
    Get-Item . | Get-CAcl -IncludeSection ([Security.AccesControl.AccessControlSections]::Access -bor [Security.AccesControl.AccessControlSections]::Owner)

    Demonstrates how to only get specific sections of the security descriptor by passing the sections to get to the
    `IncludeSection` parmeter. Also demonstrates how to get multiple sections by using the `-bor` operator to combine
    two `[System.Security.AccesControl.AccessControlSections]` values together.
    #>
    [CmdletBinding()]
    [OutputType([Security.AccessControl.NativeObjectSecurity])]
    param(
        # The registry key, file info, or directory info object whose security descriptor to get.
        [Parameter(Mandatory, ValueFromPipeline)]
        [Object] $InputObject,

        # The sections/parts of the security descriptor to get. By default, all sections are returned.
        [AccessControlSections] $IncludeSection
    )

    begin
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        if (-not $PSBoundParameters.ContainsKey('IncludeSection'))
        {
            $IncludeSection = [AccessControlSections]::All
        }
    }

    process
    {
        if ($InputObject | Get-Member -Name 'GetAccessControl' -MemberType Method)
        {
            return $InputObject.GetAccessControl($IncludeSection)
        }

        if ($InputObject -isnot [FileSystemInfo])
        {
            $msg = "Failed to get ACL for ""${InputObject}"" because it doesn't have a ""GetAccessControl"" member " +
                   "and is a [$($InputObject.GetType().FullName)] object and not a FileInfo or DirectoryInfo object."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }

        return [FileSystemAclExtensions]::GetAccessControl($InputObject, $IncludeSection)
    }
}