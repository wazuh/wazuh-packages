|Related issue|
|---|
||

<!--
This template reflects sections that must be included in new Pull requests.
Contributions from the community are really appreciated. If this is the case, please add the
"contribution" to properly track the Pull Request.

Please fill the table above. Feel free to extend it at your convenience.
-->

## Description

<!--
Add a clear description of how the problem has been solved.
-->


## Logs example

<!--
Paste here related logs
-->

## Tests


<!-- Minimum checks required -->
- Build the package in any supported platform
  - [ ] Linux
  - [ ] Windows
  - [ ] macOS
  - [ ] Solaris
  - [ ] AIX
  - [ ] HP-UX
- [ ] Package installation
- [ ] Package upgrade
- [ ] Package downgrade
- [ ] Package remove
- [ ] Package install/remove/install
- [ ] Change added to CHANGELOG.md

<!-- Depending on the affected OS -->
- Tests for Linux RPM
  - [ ] Build the package for x86_64
  - [ ] Build the package for i386
  - [ ] Build the package for armhf
  - [ ] Build the package for aarch64
  - [ ] `%files` section is correctly updated if necessary
- Tests for Linux deb
  - [ ] Build the package for x86_64
  - [ ] Build the package for i386
  - [ ] Build the package for armhf
  - [ ] Build the package for aarch64
  - [ ] Package install/remove/install
  - [ ] Package install/purge/install
  - [ ] Check file permissions after installing the package
- Tests for macOS
  - [ ] Test the package from macOS Sierra to Mojave
- Tests for Solaris
  - [ ] Test the package on Solaris 10
  - [ ] Test the package on Solaris 11
  - [ ] Check file permissions on Solaris 11 template
- Tests for IBM AIX
  - [ ] `%files` section is correctly updated if necessary
  - [ ] Check the changes from IBM AIX 5 to 7
