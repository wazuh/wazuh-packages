# Change Log
All notable changes to this project will be documented in this file.


## [v4.3.0]

- Disabled multitenancy by default in dashboard and changed the app default route [#1471](https://github.com/wazuh/wazuh-packages/pull/1471)
- Set as warning the unhandled promises in wazuh dashboard [#1434](https://github.com/wazuh/wazuh-packages/pull/1434/)
- Remove ip message from OVA [#1395](https://github.com/wazuh/wazuh-packages/pull/1395)
- Remove demo certificates from indexer and dashboard packages [#1390](https://github.com/wazuh/wazuh-packages/pull/1390)
- Add centos8 vault repository due to EOL [#1307](https://github.com/wazuh/wazuh-packages/pull/1307)
- Fix user deletion warning RPM manager [#1302](https://github.com/wazuh/wazuh-packages/pull/1302)
- Fix issue where Solaris 11 was not executed in clean installations [#1292](https://github.com/wazuh/wazuh-packages/pull/1292)
- Fix error where Wazuh could continue running after uninstalling [#1280](https://github.com/wazuh/wazuh-packages/pull/1280)
- Fix AIX partition size [#1274](https://github.com/wazuh/wazuh-packages/pull/1274)
- Fix Solaris 11 upgrade from previous packages [#1147](https://github.com/wazuh/wazuh-packages/pull/1147)
- Add new GCloud integration files to Solaris 11 [#1126](https://github.com/wazuh/wazuh-packages/pull/1126)
- Update SPECS [#689](https://github.com/wazuh/wazuh-packages/pull/689)
- Fix `find` error in CentOS 5 building [#888](https://github.com/wazuh/wazuh-packages/pull/888)
- Add new SCA files to Solaris 11 [#944](https://github.com/wazuh/wazuh-packages/pull/944)
- Improved support for ppc64le on CentOS and Debian [#915](https://github.com/wazuh/wazuh-packages/pull/975)
- Fix error with wazuh user in Debian packages [#1005](https://github.com/wazuh/wazuh-packages/pull/1005)
- Add ossec user and group during compilation [#1023](https://github.com/wazuh/wazuh-packages/pull/1023)
- Merge Wazuh Dashboard v3 [#1261](https://github.com/wazuh/wazuh-packages/pull/1261)
- Fix certs permissions in RPM [#1256](https://github.com/wazuh/wazuh-packages/pull/1256)
- [Kibana app] Support pluginPlatform.version property in the app manifest [#1208](https://github.com/wazuh/wazuh-packages/pull/1208)
- Fix certificates creation using parameters 4.3 [#1162](https://github.com/wazuh/wazuh-packages/pull/1162)
- Fix archlinux package generation parameters 4.3 [#1193](https://github.com/wazuh/wazuh-packages/pull/1193)
- Add new 2.17.1 log4j mitigation version 4.3 [#1132](https://github.com/wazuh/wazuh-packages/pull/1132)
- Fix client keys Ownership for 3.7.x and previous versions [#1123](https://github.com/wazuh/wazuh-packages/pull/1123)
- Added new log4j remediation 4.3 [#1106](https://github.com/wazuh/wazuh-packages/pull/1106)
- Fix linux wpk generation 4.3 [#1112](https://github.com/wazuh/wazuh-packages/pull/1112)
- Add log4j mitigation 4.3 [#1096](https://github.com/wazuh/wazuh-packages/pull/1096)
- Increase admin.pem cert expiration date 4.3 [#1086](https://github.com/wazuh/wazuh-packages/pull/1086)
- Remove wazuh user from unattended/OVA/AMI 4.3 [#1078](https://github.com/wazuh/wazuh-packages/pull/1078)
- Fix groupdel ossec error in upgrade to 4.3.0 [#1074](https://github.com/wazuh/wazuh-packages/pull/1074)
- Fix curl kibana.yml 4.3 [#1067](https://github.com/wazuh/wazuh-packages/pull/1067)
- Remove restore-permissions.sh from Debian Packages [#1060](https://github.com/wazuh/wazuh-packages/pull/1060)
- Bump unattended 4.3.0 [#1048](https://github.com/wazuh/wazuh-packages/pull/1048)
- Removed cd usages in unattended installer and fixed uninstaller 4.3 [#1012](https://github.com/wazuh/wazuh-packages/pull/1012)
- Add ossec user and group during compilation [#1023](https://github.com/wazuh/wazuh-packages/pull/1023)
- Removed warning and added text in wazuh-passwords-tool.sh final message 4.3 [#1020](https://github.com/wazuh/wazuh-packages/pull/1020)


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
