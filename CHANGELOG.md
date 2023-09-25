# Carbon.Permissions Changelog

## 1.0.0

### Upgrade Instructions

Replaces usages of the `Grant-CPermission` and `Test-CPermission` functions' `ApplyTo` parameters with the new
`InheritanceFlag` and `PropagationFlag` parameters. Here's a mapping:

Old ApplyTo Value                           | InheritanceFlag                  | PropagationFlag
------------------------------------------- | -------------------------------- | -------------------------------
Container                                   | None                             | None
SubContainers                               | ContainerInherit                 | InheritOnly
Leaves                                      | ObjectInherit                    | InheritOnly
ChildContainers                             | ContainerInherit                 | InheritOnly, NoPropagateInherit
ChildLeaves                                 | ObjectInherit                    | InheritOnly
ContainerAndSubContainers                   | ContainerInherit                 | None
ContainerAndLeaves                          | ObjectInherit                    | None
SubContainerAndLeaves                       | ContainerInherit,ObjectInherit   | InheritOnly
ContainerAndChildContainers                 | ContainerInherit                 | None
ContainerAndChildLeaves                     | ObjectInherit                    | None
ContainerAndChildContainersAndChildLeaves   | ContainerInherit,ObjectInherit   | NoPropagateInherit
ContainerAndSubContainersAndLeaves          | ContainerInherit,ObjectInherit   | None
ChildContainersAndChildLeaves               | ContainerInherit,ObjectInherit   | InheritOnly

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
