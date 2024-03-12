<!-- markdownlint-disable MD012 no-multiple-blanks -->
# Carbon.Security PowerShell Module


## Overview

The "Carbon.Security" module has a function get an ACLs that works across PowerShell editions.


## System Requirements

* Windows PowerShell 5.1 and .NET 4.6.1+
* PowerShell 7+


## Installing

To install globally:

```powershell
Install-Module -Name 'Carbon.Security'
Import-Module -Name 'Carbon.Security'
```

To install privately:

```powershell
Save-Module -Name 'Carbon.Security' -Path '.'
Import-Module -Name '.\Carbon.Security'
```

## Commands

* `Get-CAcl`: Gets the access control (i.e. security descriptor) for a file, directory, or registry key.
