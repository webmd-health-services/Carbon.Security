
using namespace System.Diagnostics.CodeAnalysis
using namespace System.IO
using namespace System.Security.AccessControl

# Copyright WebMD Health Services
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

# Functions should use $moduleRoot as the relative root from which to find
# things. A published module has its function appended to this file, while a
# module in development has its functions in the Functions directory.
$moduleRoot = $PSScriptRoot

$psModulesRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Modules' -Resolve
Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'Carbon.Core') `
              -Function @('Get-CPathProvider') `
              -Verbose:$false
Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'Carbon.Accounts') `
              -Function @('Resolve-CIdentity', 'Resolve-CIdentityName', 'Test-CIdentity') `
              -Verbose:$false
Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'PureInvoke' -Resolve) `
              -Function @(
                    'Invoke-AdvApiLookupPrivilegeName'
                    'Invoke-AdvApiLookupPrivilegeValue',
                    'Invoke-AdvApiLsaAddAccountRights',
                    'Invoke-AdvApiLsaClose',
                    'Invoke-AdvApiLsaEnumerateAccountRights',
                    'Invoke-AdvApiLsaOpenPolicy',
                    'Invoke-AdvApiLsaRemoveAccountRights'
              )

if (-not (Test-Path -Path 'variable:IsWindows'))
{
    [SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsWindows = $true
    [SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsMacOS = $false
    [SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsLinux = $false
}

# Store each of your module's functions in its own file in the Functions
# directory. On the build server, your module's functions will be appended to
# this file, so only dot-source files that exist on the file system. This allows
# developers to work on a module without having to build it first. Grab all the
# functions that are in their own files.
$functionsPath = Join-Path -Path $moduleRoot -ChildPath 'Functions\*.ps1'
if( (Test-Path -Path $functionsPath) )
{
    foreach( $functionPath in (Get-Item $functionsPath) )
    {
        . $functionPath.FullName
    }
}
