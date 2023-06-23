# Wazuh installer - variables
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly wazuh_major="4.5"
readonly wazuh_version="4.6.0"
readonly filebeat_version="7.10.2"
readonly wazuh_install_vesion="0.1"

## Links and paths to resources
readonly resources="https://${bucket}/${wazuh_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
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
readonly base_dest_folder="wazuh-offline"
readonly manager_deb_base_url="${base_url}/apt/pool/main/w/wazuh-manager"
readonly filebeat_deb_base_url="${base_url}/apt/pool/main/f/filebeat"
readonly filebeat_deb_package="filebeat-oss-${filebeat_version}-amd64.deb"
readonly indexer_deb_base_url="${base_url}/apt/pool/main/w/wazuh-indexer"
readonly dashboard_deb_base_url="${base_url}/apt/pool/main/w/wazuh-dashboard"
readonly manager_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_package="filebeat-oss-${filebeat_version}-x86_64.rpm"
readonly indexer_rpm_base_url="${base_url}/yum"
readonly dashboard_rpm_base_url="${base_url}/yum"
readonly wazuh_gpg_key="https://${bucket}/key/GPG-KEY-WAZUH"
readonly filebeat_config_file="${resources}/tpl/wazuh/filebeat/filebeat.yml"

adminUser="wazuh"
adminPassword="wazuh"

readonly wazuh_aio_ports=( 9200 9300 1514 1515 1516 55000 443)
readonly wazuh_indexer_ports=( 9200 9300 )
readonly wazuh_manager_ports=( 1514 1515 1516 55000 )
readonly wazuh_dashboard_port=443
