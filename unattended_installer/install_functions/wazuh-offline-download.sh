#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function offline_download() {

  common_logger "Starting Wazuh packages download."

  common_logger "Downloading Wazuh ${package_type} packages for ${arch}..."

  dest_path="${base_dest_folder}/wazuh-packages"

  if [ -d ${dest_path} ]; then
    eval "rm -f ${dest_path}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path}"
  else
    eval "mkdir -m700 -p ${dest_path}" # Create folder if it does not exist
  fi

  case "${package_type}" in
    "deb")
          # Download packages for Wazuh
          eval "curl -so ${dest_path}/${manager_deb_package} ${wazuh_deb_base_url}/${manager_deb_package}"
          common_logger "Wazuh deb package downloaded"
          # Download packages for Filebeat
          eval "curl -so ${dest_path}/${filebeat_deb_package} ${filebeat_deb_base_url}/${filebeat_deb_package}"
          common_logger "Filebeat deb package downloaded"
          # Download packages for Wazuh Indexer
          eval "curl -so ${dest_path}/${indexer_deb_package} ${indexer_deb_base_url}/${indexer_deb_package}"
          common_logger "Wazuh Indexer deb package downloaded"
          # Download packages for Wazuh Dashboard
          eval "curl -so ${dest_path}/${dashboard_deb_package} ${dashboard_deb_base_url}/${dashboard_deb_package}"
          common_logger "Wazuh Dashboard deb package downloaded"
    ;;
    "rpm")
          # Download packages for Wazuh
          eval "curl -so ${dest_path}/${manager_rpm_package} ${wazuh_rpm_base_url}/${manager_rpm_package}"
          common_logger "Wazuh rpm package downloaded"
          # Download packages for Filebeat
          eval "curl -so ${dest_path}/${filebeat_rpm_package} ${filebeat_rpm_base_url}/${filebeat_rpm_package}"
          common_logger "Filebeat rpm package downloaded"
          # Download packages for Wazuh Indexer
          eval "curl -so ${dest_path}/${indexer_rpm_package} ${indexer_rpm_base_url}/${indexer_rpm_package}"
          common_logger "Wazuh Indexer rpm package downloaded"
          # Download packages for Wazuh Dashboard
          eval "curl -so ${dest_path}/${dashboard_rpm_package} ${dashboard_rpm_base_url}/${dashboard_rpm_package}"
          common_logger "Wazuh Dashboard rpm package downloaded"
    ;;
    *)
      print_unknown_args
      exit 0
    ;;
  esac

  common_logger "The packages are in ${dest_path}"

  common_logger "Downloading Configuration Files"

  dest_path="${base_dest_folder}/wazuh-files"

  if [ -d ${dest_path} ]; then
    eval "rm -f ${dest_path}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path}"
  else
    eval "mkdir -m700 -p ${dest_path}" # Create folder if it does not exist
  fi

  eval "curl -so ${dest_path}/GPG-KEY-WAZUH https://packages.wazuh.com/key/GPG-KEY-WAZUH"

  eval "curl -so ${dest_path}/filebeat.yml ${resources}/tpl/wazuh/filebeat/filebeat.yml"

  eval "curl -so ${dest_path}/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"

  eval "curl -so ${dest_path}/wazuh-filebeat-module.tar.gz ${base_url}/filebeat/wazuh-filebeat-0.1.tar.gz"

  eval "chmod 500 ${base_dest_folder}"

  common_logger "The Configuration Files are in ${dest_path}"

  eval "tar -czf ${base_dest_folder}.tar.gz ${base_dest_folder}"

  eval "chmod -R 700 ${base_dest_folder} && rm -rf ${base_dest_folder}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/installation-guide/more-installation-alternatives/offline-installation.html"

}