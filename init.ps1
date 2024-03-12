<#
.SYNOPSIS
Gets your computer ready to develop the Carbon.Security module.

.DESCRIPTION
The init.ps1 script makes the configuraion changes necessary to get your computer ready to develop for the
Carbon.Security module. It:


.EXAMPLE
.\init.ps1

Demonstrates how to call this script.
#>
[CmdletBinding()]
param(
)

#Requires -Version 5.1
#Requires -RunAsAdministrator
Set-StrictMode -Version 'Latest'
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$psModulesRoot = Join-Path -Path $PSScriptRoot -ChildPath 'PSModules' -Resolve
if (-not (Test-Path -Path $psModulesRoot))
{
    prism install
}

Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'Carbon' -Resolve) `
              -Function ('Install-CGroup', 'Install-CUser')

$password = ConvertTo-SecureString -String 'a1b2c3d4!' -AsPlainText -Force
Install-CUser -Credential ([pscredential]::New('CarbonGrantPerms', $password)) `
              -Description 'User for Carbon Grant-CPermission tests.'
Install-CUser -Credential ([pscredential]::New('CarbonGrantPerms2', $password)) `
              -Description 'User for Carbon Grant-CPermission tests.'
Install-CUser -Credential ([pscredential]::New('CarbonTestUser', $password)) `
              -Description 'User for Carbon Grant-CPermission tests.'
Install-CUser -Credential ([pscredential]::New('CarbonTestUser1', $password)) `
              -Description 'User for Carbon Grant-CPermission tests.'

Install-CGroup -Name 'CarbonTestGroup1' -Description 'Carbon test group 1'
