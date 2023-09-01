# Carbon.Permissions Changelog

## 1.0.0

### Upgrade Instructions

Remove usages of the following functions and aliases. They are no longer exported:

* `ConvertTo-CContainerInheritanceFlags`
* `ConvertTo-CInheritanceFlag`
* `ConvertTo-InheritanceFlags`
* `ConvertTo-CPropagationFlag`
* `ConvertTo-PropagationFlags`

Replace usages of the `Carbon.Security.ContainerInheritanceFlags` with `[Carbon_Permissions_ContainerInheritanceFlags]`.
Since this is a built-in PowerShell enum, you may need to add `using module Carbon.Permissions` to your scripts. We
recommend not explicitly using this type in your code.

Replace usages of `Get-Permissions` with `Get-CPermission`.

Replace usages of `Grant-Permissions` with `Grant-CPermission`.

### Added

* Function `Get-CPermission`, migrated from Carbon.
* Function `Grant-CPermission`, migrated from Carbon.
* Function `Revoke-CPermission`, migrated from Carbon.
* Function `Test-CPermission`, migrated from Carbon.

### Changed

* The type of the `Grant-CPermission` function's `ApplyTo` parameter is now a built-in PowerShell enum,
`Carbon_Permissions_ContainerInheritanceFlags` instead of the compiled
`Carbon.Security.ContainerInheritanceFlags`.

### Removed

* Alias `Get-Permissions`. Use `Get-CPermission` instead.
* Alias `Grant-Permissions`. Use `Grant-CPermission` instead.
* Alias `ConvertTo-InheritanceFlags`.
* Command `ConvertTo-CContainerInheritanceFlags`.
* Command `ConvertTo-CInheritanceFlag`.
* Alias `ConvertTo-PropagationFlags`.
* Command `ConvertTo-CPropagationFlag`.
