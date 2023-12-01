#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) 2023, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Checks the necessary dependencies for the installation
function offline_checkDependencies() {

    dependencies=( curl tar gnupg openssl )

    common_logger "Checking installed dependencies for Offline installation."
    for dep in "${dependencies[@]}"; do
        if [ "${sys_type}" == "yum" ]; then
            eval "yum list installed 2>/dev/null | grep -q -E ^"${dep}"\\."
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/"
        fi
        
        if [ "${PIPESTATUS[0]}" != 0 ]; then
            common_logger -e "${dep} is necessary for the offline installation."
            exit 1
        fi
    done
    common_logger -d "Offline dependencies are installed."

}

# Checks the necessary files for the installation
function offline_checkPreinstallation() {

    offline_tarfile="${base_dest_folder}.tar.gz"
    common_logger "Checking ${offline_tarfile} file."
    if [ ! -f "${base_path}/${offline_tarfile}" ]; then
        common_logger -e "The ${offline_tarfile} file was not found in ${base_path}."
        exit 1
    fi
    common_logger -d "${offline_tarfile} was found correctly."

}

# Extracts the files for the offline installation and check its content
function offline_extractFiles() {

    common_logger -d "Extracting files from ${offline_tarfile}"
    eval "rm -rf ${base_path}/wazuh-offline/"
    eval "tar -xzf ${offline_tarfile} ${debug}"

    if [ ! -d "${base_path}/wazuh-offline/" ]; then
        common_logger -e "The ${offline_tarfile} file could not be decompressed."
        exit 1
    fi

    files_dir="${base_path}/wazuh-offline/wazuh-files"
    packages_dir="${base_path}/wazuh-offline/wazuh-packages"

    required_files=(
        "${files_dir}/filebeat.yml"
        "${files_dir}/GPG-KEY-WAZUH"
        "${files_dir}/wazuh-filebeat-*.tar.gz"
        "${files_dir}/wazuh-template.json"
    )
    
    if [ "${sys_type}" == "apt-get" ]; then
        required_files+=("${packages_dir}/filebeat-oss-*.deb" "${packages_dir}/wazuh-dashboard_*.deb" "${packages_dir}/wazuh-indexer_*.deb" "${packages_dir}/wazuh-manager_*.deb")
    elif [ "${sys_type}" == "rpm" ]; then
        required_files+=("${packages_dir}/filebeat-oss-*.rpm" "${packages_dir}/wazuh-dashboard_*.rpm" "${packages_dir}/wazuh-indexer_*.rpm" "${packages_dir}/wazuh-manager_*.rpm")
    fi

    for file in "${required_files[@]}"; do
        if ! compgen -G "${file}" > /dev/null; then
            common_logger -e "Missing necessary offline file: ${file}"
            exit 1
        fi
    done

    common_logger -d "Offline files extracted successfully."
}
