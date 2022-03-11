#!/bin/bash

# Program to download Wazuh manager along Open Distro for Elasticsearch installation files
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function offline_download() {
  
  common_logger "Starting Wazuh packages download."
  BASE_DEST_FOLDER="wazuh-offline"

  BASE_URL="https://packages.wazuh.com/4.x"

  BASE_RESOURCES_URL="https://packages.wazuh.com/resources/${wazuh_version}"

  WAZUH_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-manager"
  WAZUH_DEB_PACKAGES=( "wazuh-manager_${wazuh_version}-1_amd64.deb" )

  FILEBEAT_DEB_BASE_URL="${BASE_URL}/apt/pool/main/f/filebeat"
  FILEBEAT_DEB_PACKAGES=( "filebeat-oss-${filebeat_version}-amd64.deb" )

  INDEXER_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-indexer"
  INDEXER_DEB_PACKAGES=( "wazuh-indexer_${wazuh_version}-1_amd64.deb" )

  DASHBOARD_DEB_BASE_URL="${BASE_URL}/apt/pool/main/w/wazuh-dashboard"
  DASHBOARD_DEB_PACKAGES=( "wazuh-dashboard_${wazuh_version}-1_amd64.deb" )

  WAZUH_RPM_BASE_URL="${BASE_URL}/yum"
  WAZUH_RPM_PACKAGES=( "wazuh-manager-${wazuh_version}-1.x86_64.rpm" )

  FILEBEAT_RPM_BASE_URL="${BASE_URL}/yum"
  FILEBEAT_RPM_PACKAGES=( "filebeat-oss-${filebeat_version}-x86_64.rpm" )

  INDEXER_RPM_BASE_URL="${BASE_URL}/yum"
  INDEXER_RPM_PACKAGES=( "wazuh-indexer-${wazuh_version}-1.x86_64.rpm" )

  DASHBOARD_RPM_BASE_URL="${BASE_URL}/yum"
  DASHBOARD_RPM_PACKAGES=( "wazuh-dashboard-${wazuh_version}-1.x86_64.rpm" )

  printf "\nDownloading Wazuh $package_type packages for $ARCH...\n"

  DEST_PATH="${BASE_DEST_FOLDER}/wazuh-packages"

  mkdir -p ${DEST_PATH} # Create folder if it does not exist

  rm -f${VERBOSE} ${DEST_PATH}/* # Clean folder before downloading specific versions

  case "$package_type" in
    "deb")
      for p in ${WAZUH_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh
          curl -so ${DEST_PATH}/$p ${WAZUH_DEB_BASE_URL}/$p
      done
      
      for p in ${FILEBEAT_DEB_PACKAGES[@]}; do
          # Download packages for Filebeat
          curl -so ${DEST_PATH}/$p ${FILEBEAT_DEB_BASE_URL}/$p
      done
      for p in ${INDEXER_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh Indexer
          curl -so ${DEST_PATH}/$p ${INDEXER_DEB_BASE_URL}/$p
      done
      for p in ${DASHBOARD_DEB_PACKAGES[@]}; do
          # Download packages for Wazuh Dashboard
          curl -so ${DEST_PATH}/$p ${DASHBOARD_DEB_BASE_URL}/$p
      done
    ;;
    "rpm")
      for p in ${WAZUH_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh
          curl -so ${DEST_PATH}/$p ${WAZUH_RPM_BASE_URL}/$p
      done
      for p in ${FILEBEAT_RPM_PACKAGES[@]}; do
          # Download packages for Filebeat
          curl -so ${DEST_PATH}/$p ${FILEBEAT_RPM_BASE_URL}/$p
      done
      for p in ${INDEXER_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh Indexer
          curl -so ${DEST_PATH}/$p ${INDEXER_RPM_BASE_URL}/$p
      done
      for p in ${DASHBOARD_RPM_PACKAGES[@]}; do
          # Download packages for Wazuh Dashboard
          curl -so ${DEST_PATH}/$p ${DASHBOARD_RPM_BASE_URL}/$p
      done
    ;;
    *)
      print_unknown_args
      exit 0
    ;;
  esac

}