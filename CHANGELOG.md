# Carbon.Security Changelog

## 1.0.0

### Upgrade Instructions

This is not the upgrade path you want, if switching from Carbon. The `Get-CPermission`, `Grant-CPermission`,
`Revoke-CPermission`, and `Test-CPermission` functions were migrated to the following provider-specific modules with the
following function names:

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

### Added

* Function `Get-CAcl` to get the access control (i.e. security descriptor) for a registry key, file, or directory.
Supports getting only specific sections/parts of the security descriptor, too. Works across PowerShell editions.
