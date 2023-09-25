<!-- markdownlint-disable MD012 no-multiple-blanks -->
# Carbon.Permissions PowerShell Module


## Overview

The "Carbon.Permissions" module manages permissions on files, directories, registry keys, and certificate private
keys/key containers.


## System Requirements

* Windows PowerShell 5.1 and .NET 4.6.1+
* PowerShell 7+


## Installing

To install globally:

```powershell
Install-Module -Name 'Carbon.Permissions'
Import-Module -Name 'Carbon.Permissions'
```

To install privately:

```powershell
Save-Module -Name 'Carbon.Permissions' -Path '.'
Import-Module -Name '.\Carbon.Permissions'
```

## Commands

* `Get-CAcl`: Gets the access control (i.e. security descriptor) for a file, directory, or registry key.
* `Get-CPermission`: Gets the permissions (access control rules) for a file, directory, registry key, or certificate
  private key/key container.
* `Grant-CPermission`: Grants permissions on a file, directory, registry key, or certificate private key/key container.
* `Revoke-CPermission`: Revokes permissions on a file, directory, registry key, or certificate private key/key
  container.
* `Test-CPermission`: Tests permissions on a file, directory, registry key, or certificate private key/key container.
