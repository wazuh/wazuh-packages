# Change Log
All notable changes to this project will be documented in this file.

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
