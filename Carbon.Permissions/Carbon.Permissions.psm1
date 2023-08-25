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
              -Function @('Add-CTypeData', 'Get-CPathProvider')
Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'Carbon.Accounts') `
              -Function @('Resolve-CPrincipalName', 'Test-CPrincipal')

if (-not (Test-Path -Path 'variable:IsWindows'))
{
    $IsWindows = $true
    $IsMacOS = $IsLinux = $true
}

$ConfirmPreference
[Flags()]
enum Carbon_Permissions_ContainerInheritanceFlags
{
    # Apply permission to the container.
    Container = 0x1

    # Apply permissions to all sub-containers.
    SubContainers = 0x2

    # Apply permissions to all leaves.
    Leaves = 0x4

    # Apply permissions to child containers.
    ChildContainers = 0x8

    # Apply permissions to child leaves.
    ChildLeaves = 0x10

    # Apply permission to the container and all sub-containers.
    ContainerAndSubContainers = 0x1 -bor 0x2

    # Apply permissionto the container and all leaves.
    ContainerAndLeaves = 0x1 -bor 0x4

    # Apply permission to all sub-containers and all leaves.
    SubContainersAndLeaves = 0x2  -bor 0x4

    # Apply permission to container and child containers.
    ContainerAndChildContainers = 0x1 -bor 0x8

    # Apply permission to container and child leaves.
    ContainerAndChildLeaves = 0x1 -bor 0x10

    # Apply permission to container, child containers, and child leaves.
    ContainerAndChildContainersAndChildLeaves = 0x1 -bor 0x8 -bor 0x10

    # Apply permission to container, all sub-containers, and all leaves.
    ContainerAndSubContainersAndLeaves = 0x1 -bor 0x2 -bor 0x4

    # Apply permission to child containers and child leaves.
    ChildContainersAndChildLeaves = 0x8 -bor 0x10
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
