# Wazuh installer - variables
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly wazuh_major="4.3"
readonly wazuh_version="4.3.0"
readonly wazuh_revision="1"
readonly filebeat_version="7.10.2"
readonly wazuh_install_vesion="0.1"
readonly bucket="packages-dev.wazuh.com"
readonly repository="pre-release" #use 4.x for production

## Links and paths to resources
readonly resources="https://${bucket}/${wazuh_major}"
readonly BASE_URL="https://${bucket}/${repository}"
readonly base_path="$(dirname $(readlink -f "$0"))"
config_file="${base_path}/config.yml"
readonly tar_file_name="wazuh-install-files.tar"
tar_file="${base_path}/${tar_file_name}"

readonly filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"

readonly dashboard_cert_path="/etc/wazuh-dashboard/certs"
readonly filebeat_cert_path="/etc/filebeat/certs"
readonly indexer_cert_path="/etc/wazuh-indexer/certs"

readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"

## Offline Installation vars
readonly BASE_DEST_FOLDER="wazuh-offline"
readonly WAZUH_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-manager"
readonly WAZUH_DEB_PACKAGES=( "wazuh-manager_${wazuh_version}-${wazuh_revision}_amd64.deb" )
readonly FILEBEAT_DEB_BASE_URL="${BASE_URL}/apt/pool/main/f/filebeat"
readonly FILEBEAT_DEB_PACKAGES=( "filebeat-oss-${filebeat_version}-amd64.deb" )
readonly INDEXER_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-indexer"
readonly INDEXER_DEB_PACKAGES=( "wazuh-indexer_${wazuh_version}-${wazuh_revision}_amd64.deb" )
readonly DASHBOARD_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-dashboard"
readonly DASHBOARD_DEB_PACKAGES=( "wazuh-dashboard_${wazuh_version}-${wazuh_revision}_amd64.deb" )
readonly WAZUH_RPM_BASE_URL="${BASE_URL}/yum"
readonly WAZUH_RPM_PACKAGES=( "wazuh-manager-${wazuh_version}-${wazuh_revision}.x86_64.rpm" )
readonly FILEBEAT_RPM_BASE_URL="${BASE_URL}/yum"
readonly FILEBEAT_RPM_PACKAGES=( "filebeat-oss-${filebeat_version}-x86_64.rpm" )
readonly INDEXER_RPM_BASE_URL="${BASE_URL}/yum"
readonly INDEXER_RPM_PACKAGES=( "wazuh-indexer-${wazuh_version}-${wazuh_revision}.x86_64.rpm" )
readonly DASHBOARD_RPM_BASE_URL="${BASE_URL}/yum"
readonly DASHBOARD_RPM_PACKAGES=( "wazuh-dashboard-${wazuh_version}-${wazuh_revision}.x86_64.rpm" )
