# Carbon.Security Changelog

## 1.0.1

Decreasing depth of nested dependencies.

## 1.0.0

> Released 10 Jun 2024

### Upgrade Instructions

If switching from Carbon, the `Get-CPermission`, `Grant-CPermission`, `Revoke-CPermission`, and `Test-CPermission`
functions were migrated to the following provider-specific modules with the following function names:

`Carbon.FileSystem`:

* `Get-CNtfsPermission`
* `Grant-CNtfsPermission`
* `Revoke-CNtfsPermission`
* `Test-CNtfsPermission`

`Carbon.Registry`:

* `Get-CRegistryPermission`
* `Grant-CRegistryPermission`
* `Revoke-CRegistryPermission`
* `Test-CRegistryPermission`:

`Carbon.Cryptography`:

* `Get-CPrivateKey`
* `Get-CPrivateKeyPermission`
* `Grant-CPrivateKeyPermission`
* `Resolve-CPrivateKeyPath`
* `Revoke-CPrivateKeyPermission`
* `Test-CPrivateKeyPath`
* `Test-CPrivateKeyPermission`

### Added

* Function `Get-CAcl` to get the access control (i.e. security descriptor) for a registry key, file, or directory.
Supports getting only specific sections/parts of the security descriptor, too. Works across PowerShell editions.
* Function `Get-CPrivilege` (migrated from Carbon), which gets a user/group's rights/privileges.
* Function `Grant-CPrivilege` (migrated from Carbon), which grants a user/group rights/privileges.
* Function `Revoke-CPrivilege` (migrated from Carbon), which removes a user/group's rights/privileges.
* Function `Test-CPrivilege` (migrated from Carbon), which tests a user/group's rights/privileges.
* Function `Test-CPrivilegeName`, which tests if rights/privileges are supported on the current operating system.

### Changed

* The `Privilege` parameters on the `Grant-CPrivilege` and `Revoke-CPrivilege` functions are now case-insensitive.
