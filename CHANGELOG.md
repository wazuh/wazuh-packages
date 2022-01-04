# Change Log
All notable changes to this project will be documented in this file.


## [v4.4.0]

- Update SPECS [#1014](https://github.com/wazuh/wazuh-packages/pull/1014)

## [v4.3.0]

- Fix Solaris 11 upgrade from previous packages [#1147](https://github.com/wazuh/wazuh-packages/pull/1147)
- Add new GCloud integration files to Solaris 11 [#1126](https://github.com/wazuh/wazuh-packages/pull/1126)
- Update SPECS [#689](https://github.com/wazuh/wazuh-packages/pull/689)
- Fix `find` error in CentOS 5 building [#888](https://github.com/wazuh/wazuh-packages/pull/888)
- Add new SCA files to Solaris 11 [#944](https://github.com/wazuh/wazuh-packages/pull/944)
- Improved support for ppc64le on CentOS and Debian [#915](https://github.com/wazuh/wazuh-packages/pull/975)
- Fix error with wazuh user in Debian packages [#1005](https://github.com/wazuh/wazuh-packages/pull/1005)

## [v4.2.5]

- Update SPECS [#991](https://github.com/wazuh/wazuh-packages/pull/991)

## [v4.2.4]

- Update SPECS [#927](https://github.com/wazuh/wazuh-packages/pull/927)

## [v4.2.3]

- Update SPECS [#915](https://github.com/wazuh/wazuh-packages/pull/915)


## [v4.2.2]

- Update SPECS [#846](https://github.com/wazuh/wazuh-packages/pull/846)

## [v4.2.1]

- Update SPECS [#833](https://github.com/wazuh/wazuh-packages/pull/833)

## [v4.2.0]

- Update SPECS [#556](https://github.com/wazuh/wazuh-packages/pull/556)

## [v4.1.5]

- Update SPECS [#726](https://github.com/wazuh/wazuh-packages/pull/726)

## [v4.1.4]

- Update SPECS [#684](https://github.com/wazuh/wazuh-packages/pull/684)

## [v4.1.3]

- Update SPECS [#668](https://github.com/wazuh/wazuh-packages/pull/668)

## [v4.1.2]

- Update SPECS [#656](https://github.com/wazuh/wazuh-packages/pull/656)

## [v4.1.1]

- Updated Wazuh app build script [#648](https://github.com/wazuh/wazuh-packages/pull/648)

## [v4.0.2]

### Added

- Added a new welcome message to Wazuh VM ([#535](https://github.com/wazuh/wazuh-packages/pull/535)).

### Fixed

- Fixed the group of the `ossec.conf` in IBM AIX package ([#541](https://github.com/wazuh/wazuh-packages/pull/541)).

## [v4.0.1]

### Fixed

- Added new SSL certificates to secure Kibana communications and ensure HTTPS access to the UI ([#534](https://github.com/wazuh/wazuh-packages/pull/534)).

## [v4.0.0]

### Added

- Added Open Distro for Elasticsearch packages to Wazuh's software repository.

### Changed

- Wazuh services are no longer enabled nor started in a fresh install ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
- Wazuh services will be restarted on upgrade if they were running before upgrading them ([#481](https://github.com/wazuh/wazuh-packages/pull/481)) and ([#482](https://github.com/wazuh/wazuh-packages/pull/482)).
- Wazuh API and Wazuh Manager services are unified in a single `wazuh-manager` service ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
- Wazuh app for Splunk and Wazuh plugin for Kibana have been renamed ([#479](https://github.com/wazuh/wazuh-packages/pull/479)).
- Wazuh VM now uses Wazuh and Open Distro for Elasticsearch ([#462](https://github.com/wazuh/wazuh-packages/pull/462)).

### Fixed

- Unit files for systemd are now installed on `/usr/lib/systemd/system` ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
- Unit files are now correctly upgraded ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
- `ossec-init.conf` file now shows the build date for any system ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
- Fixed an error setting SCA file permissions on .deb packages ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).

### Removed

- Wazuh API package has been removed. Now, the Wazuh API is embedded into the Wazuh Manager installation ([wazuh/wazuh#5721](https://github.com/wazuh/wazuh/pull/5721)).
- Removed OpenSCAP files and integration ([#466](https://github.com/wazuh/wazuh-packages/pull/466)).
