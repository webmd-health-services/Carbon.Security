# Carbon.Permissions Changelog

## 1.0.0

### Upgrade Instructions

Replaces usages of the `Grant-CPermission` and `Test-CPermission` functions' `ApplyTo` parameter with new parameter
values and a new `OnlyApplyToChildren` switch:

| Old Parameters                                     | New Parameters
| -------------------------------------------------- | --------------
| -ApplyTo Container                                 | -ApplyTo ContainerOnly
| -ApplyTo SubContainers                             | -ApplyTo SubcontainersOnly
| -ApplyTo Leaves                                    | -ApplyTo LeavesOnly
| -ApplyTo ChildContainers                           | -ApplyTo SubcontainersOnly -OnlyApplyToChildren
| -ApplyTo ChildLeaves                               | -ApplyTo LeavesOnly -OnlyApplyToChildren
| -ApplyTo ContainerAndSubContainers                 | -ApplyTo ContainerAndSubcontainers
| -ApplyTo ContainerAndLeaves                        | -ApplyTo ContainerAndLeaves
| -ApplyTo SubContainerAndLeaves                     | -ApplyTo SubcontainersAndLeavesOnly
| -ApplyTo ContainerAndChildContainers               | -ApplyTo ContainerAndSubcontainers -OnlyApplyToChildren
| -ApplyTo ContainerAndChildLeaves                   | -ApplyTo ContainerAndLeaves -OnlyApplyToChildren
| -ApplyTo ContainerAndChildContainersAndChildLeaves | -ApplyTo ContainerSubcontainersAndLeaves -OnlyApplyToChildren
| -ApplyTo ContainerAndSubContainersAndLeaves        | -ApplyTo ContainerSubcontainersAndLeaves
| -ApplyTo ChildContainersAndChildLeaves             | -ApplyTo SubcontainersAndLeavesOnly -OnlyApplyToChildren

Replace usages of `Get-Permissions` with `Get-CPermission`.

Replace usages of `Grant-Permissions` with `Grant-CPermission`.

Rename usages of the `Get-CPermission` and `Test-CPermission` functions' `Exact` switch to `Strict`.

### Added

* Function `Get-CPermission`, migrated from Carbon.
* Function `Grant-CPermission`, migrated from Carbon.
* Function `Revoke-CPermission`, migrated from Carbon.
* Function `Test-CPermission`, migrated from Carbon.
* Function `Get-CAcl` to get the access control (i.e. security descriptor) for a registry key, file, or directory.
Supports getting only specific sections/parts of the security descriptor, too.

### Changed

* Switch `Exact` renamed to `Strict` on the `Get-CPermission` and `Test-CPermission` functions.

### Removed

* The `ApplyTo` function on `Grant-CPermission` and `Test-CPermission`. Use the new `InheritanceFlag` and
`PropagationFlag` parameters to set a permission's inheritance and propagation flags.
* Alias `Get-Permissions`. Use `Get-CPermission` instead.
* Alias `Grant-Permissions`. Use `Grant-CPermission` instead.
