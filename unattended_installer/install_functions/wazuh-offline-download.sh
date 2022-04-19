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

  DEST_PATH="${BASE_DEST_FOLDER}/wazuh-packages"

  if [ -d ${DEST_PATH} ]; then
    eval "rm -f ${VERBOSE} ${DEST_PATH}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${DEST_PATH}"
  else
    eval "mkdir -m700 -p ${DEST_PATH}" # Create folder if it does not exist
  fi

  case "${package_type}" in
    "deb")
      for p in ${WAZUH_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh
          eval "curl -so ${DEST_PATH}/$p ${WAZUH_DEB_BASE_URL}/$p"
          common_logger "Wazuh deb package downloaded"
      done

      for p in ${FILEBEAT_DEB_PACKAGES[@]}; do
          # Download packages for Filebeat
          eval "curl -so ${DEST_PATH}/$p ${FILEBEAT_DEB_BASE_URL}/$p"
          common_logger "Filebeat deb package downloaded"
      done
      for p in ${INDEXER_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh Indexer
          eval "curl -so ${DEST_PATH}/$p ${INDEXER_DEB_BASE_URL}/$p"
          common_logger "Wazuh Indexer deb package downloaded"
      done
      for p in ${DASHBOARD_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh Dashboard
          eval "curl -so ${DEST_PATH}/$p ${DASHBOARD_DEB_BASE_URL}/$p"
          common_logger "Wazuh Dashboard deb package downloaded"
      done
    ;;
    "rpm")
      for p in ${WAZUH_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh
          eval "curl -so ${DEST_PATH}/$p ${WAZUH_RPM_BASE_URL}/$p"
          common_logger "Wazuh rpm package downloaded"
      done
      for p in ${FILEBEAT_RPM_PACKAGES[@]}; do
          # Download packages for Filebeat
          eval "curl -so ${DEST_PATH}/$p ${FILEBEAT_RPM_BASE_URL}/$p"
          common_logger "Filebeat rpm package downloaded"
      done
      for p in ${INDEXER_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh Indexer
          eval "curl -so ${DEST_PATH}/$p ${INDEXER_RPM_BASE_URL}/$p"
          common_logger "Wazuh Indexer rpm package downloaded"
      done
      for p in ${DASHBOARD_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh Dashboard
          eval "curl -so ${DEST_PATH}/$p ${DASHBOARD_RPM_BASE_URL}/$p"
          common_logger "Wazuh Dashboard rpm package downloaded"
      done
    ;;
    *)
      print_unknown_args
      exit 0
    ;;
  esac

  common_logger "The packages are in ${DEST_PATH}"

  common_logger "Downloading Configuration Files"

  DEST_PATH="${BASE_DEST_FOLDER}/wazuh-files"

  if [ -d ${DEST_PATH} ]; then
    eval "rm -f ${VERBOSE} ${DEST_PATH}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${DEST_PATH}"
  else
    eval "mkdir -m700 -p ${DEST_PATH}" # Create folder if it does not exist
  fi

  eval "curl -so ${DEST_PATH}/GPG-KEY-WAZUH https://packages.wazuh.com/key/GPG-KEY-WAZUH"

  eval "curl -so ${DEST_PATH}/filebeat.yml ${resources}/tpl/wazuh/filebeat/filebeat.yml"

  eval "curl -so ${DEST_PATH}/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"

  eval "curl -so ${DEST_PATH}/wazuh-filebeat-module.tar.gz ${BASE_URL}/filebeat/wazuh-filebeat-0.1.tar.gz"

  eval "chmod 500 ${BASE_DEST_FOLDER}"

  common_logger "The Configuration Files are in ${DEST_PATH}"

  eval "tar -czf ${BASE_DEST_FOLDER}.tar.gz ${BASE_DEST_FOLDER}"

  eval "chmod -R 700 ${BASE_DEST_FOLDER} && rm -rf ${BASE_DEST_FOLDER}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/installation-guide/more-installation-alternatives/offline-installation.html"

}