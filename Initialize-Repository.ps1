[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [String] $ModuleName,

    [Parameter(Mandatory)]
    [String] $ModuleDescription,

    [Parameter(Mandatory)]
    [String] $GitHubOrganizationName
)

Set-StrictMode -Version 'Latest'
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

[IO.Directory]::SetCurrentDirectory($PSScriptRoot)

$rootPath = $PSScriptRoot | Resolve-Path -Relative

Write-Information ("Replacing ""MODULE_NAME"" with ""$($ModuleName)"" in file/directory names.")
$getChildItemPath = Join-Path -Path $rootPath -ChildPath '*'
$filesWithModuleName =
    Get-ChildItem -Path $getChildItemPath -Recurse -Filter "*MODULE_NAME*" |
    Sort-Object -Property { $_.FullName.Length } -Descending
foreach( $file in $filesWithModuleName )
{
    $newName = $file.Name -replace 'MODULE_NAME',$ModuleName
    Write-Information -Message ("  $($file.FullName | Resolve-Path -Relative) -> $($newName)")
    Rename-Item -Path $file.FullName -NewName $newName
}

$readmePath = Join-Path -Path $rootPath -ChildPath 'README.md'
$todoPath = Join-Path -Path $rootPath -ChildPath 'TODO.md'
if( (Test-Path -Path $readmePath) -and -not (Test-Path -Path $todoPath) )
{
    Write-Information ('Putting TODO.md in place.')
    Rename-Item -Path $readmePath -NewName ($todoPath | Split-Path -Leaf)
}

Write-Information ("Removing ""MODULE_"" prefix in file/directory names.")
$filesWithModulePrefix =
    Get-ChildItem -Path $getChildItemPath -Recurse -Filter "MODULE_*" |
    Sort-Object -Property { $_.FullName.Length } -Descending
foreach( $file in $filesWithModulePrefix )
{
    $newName = $file.Name -replace 'MODULE_', ''
    $newPath = Join-Path -Path $file.Directory.FullName -ChildPath $newName
    if( (Test-Path -Path $newPath) )
    {
        Write-Information -Message ("  Deleting $($newPath | Resolve-Path -Relative)")
        Remove-Item -Path $newPath -Force
    }
    Write-Information -Message ("  $($file.FullName | Resolve-Path -Relative) -> $($newName)")
    Rename-Item -Path $file.FullName -NewName $newName
}

$moduleGuid = [Guid]::NewGuid()
Write-Information ("Replacing ""MODULE_NAME"" -> ""$($ModuleName)"" in file contents.")
$repoFiles = Get-ChildItem -Path $getChildItemPath -Exclude '.git' -Recurse -File
foreach( $repoFile in $repoFiles )
{
    $filePath = $repoFile.FullName | Resolve-Path -Relative
    $newText = $text = Get-Content -Path $filePath -Raw
    $newText = $newText -creplace 'MODULE_NAME',$ModuleName
    $newText = $newText -creplace 'MODULE_GUID',$moduleGuid
    $newText = $newText -creplace 'MODULE_DESCRIPTION',$ModuleDescription
    $newText = $newText -creplace 'GITHUB_ORGANIZATION_NAME',$GitHubOrganizationName
    $newText = $newText -creplace '\[YYYY\]', (Get-Date).Year
    if( $text -ne $newText -and $PSCmdlet.ShouldProcess($filePath, "replace MODULE_NAME -> $($ModuleName)") )
    {
        Write-Verbose -Message "  $($filePath)"
        [IO.File]::WriteAllText($filePath, $newText)
    }
}

if( -not (Test-Path -Path (Join-Path -Path $rootPath -ChildPath 'build.ps1')) )
{
    Write-Information "Installing and enabling Whiskey."
    if( $PSCmdlet.ShouldProcess($rootPath, 'installing and enabling Whiskey') )
    {
        $uri = 'https://github.com/webmd-health-services/Whiskey/releases/latest/download/build.ps1'
        Invoke-WebRequest -Uri $uri -OutFile 'build.ps1'
    }
}

Write-Information ("Removing ""$($PSCommandPath | Resolve-Path -Relative)"".")
Remove-Item -Path $PSCommandPath

if( (Get-Command -Name 'git' -ErrorAction Ignore) )
{
    Write-Information 'Adding new files to Git repository.'
    if( $PSCmdlet.ShouldProcess($rootPath, 'git add *') )
    {
        git add *
    }

    Write-Information 'Committing changes to repository''s initial commit.'
    if( $PSCmdlet.ShouldProcess($rootPath, 'git commit --amend') )
    {
        git commit --amend -m "Initial commit."
    }

    Write-Information 'Pushing changes.'
    if( $PSCmdlet.ShouldProcess($rootPath, 'git push -f') )
    {
        git push -f
    }
}
else
{
    $msg = 'Changes haven''t been committed yet (couldn''t find Git executable). Run `git add *` then ' +
           '`git commit --amend -m "Initial commit."` and finally `git push` to complete the changes.'
    Write-Warning $msg
}

Write-Information ('Repository initialized. Please see the TODO.md file for next steps.')
