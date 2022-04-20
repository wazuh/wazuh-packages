#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function offline_download() {

  common_logger "Starting Wazuh packages download."
  common_logger "Downloading Wazuh ${package_type} packages for ${arch}."
  dest_path="${base_dest_folder}/wazuh-packages"

  if [ -d ${dest_path} ]; then
    eval "rm -f ${dest_path}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path}"
  else
    eval "mkdir -m700 -p ${dest_path}" # Create folder if it does not exist
  fi

  packages_to_download=( "manager" "filebeat" "indexer" "dashboard" )

  for package in "${packages_to_download[@]}"
  do

    package_name="${package}_${package_type}_package"
    eval "package_base_url="${package}_${package_type}_base_url""

    eval "curl -so ${dest_path}/${package_name} ${package_base_url}/${package_name}"
    if [  "$?" != 0  ]; then
        common_logger -e "The ${package} package could not be downloaded. Exiting."
        exit 1
    else
        common_logger "The ${package} package was downloaded."
    fi

  done

  common_logger "The packages are in ${dest_path}"

# --------------------------------------------------

  common_logger "Downloading configuration files and assets."
  dest_path="${base_dest_folder}/wazuh-files"

  if [ -d ${dest_path} ]; then
    eval "rm -f ${dest_path}/*" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path}"
  else
    eval "mkdir -m700 -p ${dest_path}" # Create folder if it does not exist
  fi

  files_to_download=( "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
                      "${resources}/tpl/wazuh/filebeat/filebeat.yml"
                      "https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
                      "${base_url}/filebeat/wazuh-filebeat-0.1.tar.gz" )

  cd ${dest_path}
  for file in "${files_to_download[@]}"
  do

    eval "curl -sO ${files_to_download}"
    if [  "$?" != 0  ]; then
        common_logger -e "The resource ${files_to_download} could not be downloaded. Exiting."
        exit 1
    else
        common_logger "The resource ${files_to_download} was downloaded."
    fi

  done
  cd -

  eval "chmod 500 ${base_dest_folder}"

  common_logger "The configuration files and assets are in ${dest_path}"

  eval "tar -czf ${base_dest_folder}.tar.gz ${base_dest_folder}"
  eval "chmod -R 700 ${base_dest_folder} && rm -rf ${base_dest_folder}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/installation-guide/more-installation-alternatives/offline-installation.html"

}