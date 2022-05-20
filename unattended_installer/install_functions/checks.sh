# Wazuh installer - checks.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function checks_arch() {

    arch=$(uname -m)

    if [ "${arch}" != "x86_64" ]; then
        common_logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

function checks_arguments() {

    # -------------- Configurations ---------------------------------

    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            rm -f "${tar_file}"
        fi
        if [ -n "${configurations}" ]; then
            common_logger -e "File ${tar_file} already exists. Please remove it if you want to use a new configuration."
            exit 1
        fi
    fi

    if [[ -n "${configurations}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${start_indexer_cluster}" || -n "${tar_conf}" || -n "${uninstall}" ) ]]; then
        common_logger -e "The argument -g|--generate-config-files can't be used with -a|--all-in-one, -o|--overwrite, -s|--start-cluster, -t|--tar, -u|--uninstall, -wd|--wazuh-dashboard, -wi|--wazuh-indexer, or -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Overwrite --------------------------------------

    if [ -n "${overwrite}" ] && [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ]; then 
        common_logger -e "The argument -o|--overwrite must be used in conjunction with -a|--all-in-one, -wd|--wazuh-dashboard, -wi|--wazuh-indexer, or -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Uninstall --------------------------------------

    if [ -n "${uninstall}" ]; then

        if [ -n "$AIO" ] || [ -n "$indexer" ] || [ -n "$dashboard" ] || [ -n "$wazuh" ]; then
            common_logger -e "It is not possible to uninstall and install in the same operation. If you want to overwrite the components use -o|--overwrite."
            exit 1
        fi

        if [ -z "${wazuh_installed}" ] && [ -z "${wazuh_remaining_files}" ]; then
            common_logger "Wazuh manager not found in the system so it was not uninstalled."
        fi

        if [ -z "${filebeat_installed}" ] && [ -z "${filebeat_remaining_files}" ]; then
            common_logger "Filebeat not found in the system so it was not uninstalled."
        fi

        if [ -z "${indexer_installed}" ] && [ -z "${indexer_remaining_files}" ]; then
            common_logger "Wazuh Indexer not found in the system so it was not uninstalled."
        fi

        if [ -z "${dashboard_installed}" ] && [ -z "${dashboard_remaining_files}" ]; then
            common_logger "Wazuh Dashboard not found in the system so it was not uninstalled."
        fi

    fi

    # -------------- All-In-One -------------------------------------

    if [ -n "${AIO}" ]; then

        if [ -n "$indexer" ] || [ -n "$dashboard" ] || [ -n "$wazuh" ]; then
            common_logger -e "Argument -a|--all-in-one is not compatible with -wi|--wazuh-indexer, -wd|--wazuh-dashboard or -ws|--wazuh-server."
            exit 1
        fi

        if [ -n "${overwrite}" ]; then
            installCommon_rollBack
        fi

        if [ -z "${overwrite}" ] && ([ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ]); then
            common_logger -e "Wazuh manager already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && ([ -n "${indexer_installed}" ] || [ -n "${indexer_remaining_files}" ]);then 
            common_logger -e "Wazuh indexer already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && ([ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]); then
            common_logger -e "Wazuh dashboard already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && ([ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]); then
            common_logger -e "Filebeat already installed."
            installedComponent=1
        fi
        if [ -n "${installedComponent}" ]; then
            common_logger "If you want to overwrite the current installation, run this script adding the option -o/--overwrite. This will erase all the existing configuration and data."
            exit 1
        fi

    fi

    # -------------- Indexer ----------------------------------

    if [ -n "${indexer}" ]; then

        if [ -n "${indexer_installed}" ] || [ -n "${indexer_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh Indexer is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh Dashboard --------------------------------

    if [ -n "${dashboard}" ]; then
        if [ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh Dashboard is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh ------------------------------------------

    if [ -n "${wazuh}" ]; then
        if [ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi

        if [ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Filebeat is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Cluster start ----------------------------------

    if [[ -n "${start_indexer_cluster}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${configurations}" || -n "${tar_conf}" || -n "${uninstall}") ]]; then
        common_logger -e "The argument -s|--start-cluster can't be used with -a|--all-in-one, -g|--generate-config-files,-o|--overwrite , -u|--uninstall, -wi|--wazuh-indexer, -wd|--wazuh-dashboard, -s|--start-cluster, -ws|--wazuh-server."
        exit 1
    fi

    # -------------- Global -----------------------------------------

    if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ] && [ -z "${configurations}" ] && [ -z "${uninstall}" ] && [ -z "${download}" ]; then
        common_logger -e "At least one of these arguments is necessary -a|--all-in-one, -g|--generate-config-files, -wi|--wazuh-indexer, -wd|--wazuh-dashboard, -s|--start-cluster, -ws|--wazuh-server, -u|--uninstall, -dw|--download-wazuh."
        exit 1
    fi

    if [ -n "${force}" ] && [ -z  "${dashboard}" ]; then
        common_logger -e "The -fd|--force-install-dashboard argument needs to be used alongside -wd|--wazuh-dashboard."
        exit 1
    fi 

}

function check_dist() {
    dist_detect
    if [ "${DIST_NAME}" != "centos" ] && [ "${DIST_NAME}" != "rhel" ] && [ "${DIST_NAME}" != "amzn" ] && [ "${DIST_NAME}" != "ubuntu" ]; then
        notsupported=1
    fi
    if ([ "${DIST_NAME}" == "centos" ] || [ "${DIST_NAME}" == "rhel" ]) && ([ "${DIST_VER}" -ne "7" ] && [ "${DIST_VER}" -ne "8" ]); then
        notsupported=1
    fi
    if ([ "${DIST_NAME}" == "amzn" ]) && ([ "${DIST_VER}" -ne "2" ]); then
        notsupported=1
    fi
    if ([ "${DIST_NAME}" == "ubuntu" ]) && ([ "${DIST_VER}" -ne "16" ] && [ "${DIST_VER}" -ne "18" ] && [ "${DIST_VER}" -ne "20" ]); then
        notsupported=1
    fi
    if ([ "${DIST_NAME}" == "ubuntu" ]) && ([ "${DIST_VER}" -eq "16" ] || [ "${DIST_VER}" -eq "18" ] || [ "${DIST_VER}" -eq "20" ]) &&  ([ "${DIST_SUBVER}" != "04" ]); then
        notsupported=1
    fi
    if [ -n "${notsupported}" ] && [ -z "${ignore}" ]; then
        common_logger -e "The recommended systems are: Red Hat Enterprise Linux 7, 8; CentOS 7, 8; Amazon Linux 2; Ubuntu 16.04, 18.04, 20.04. The current system doesn't match this list. Use -i|--ignore-check to skip this check."
        exit 1
    fi
}

function checks_health() {

    logger "Verifying that your system meets the recommended minimum hardware requirements."
    
    checks_specifications

    if [ -n "${indexer}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${dashboard}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${wazuh}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 1700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

    if [ -n "${AIO}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            common_logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        fi
    fi

}

# This function ensures different names in the config.yml file.
function checks_names() {

    if [ -n "${indxname}" ] && [ -n "${dashname}" ] && [ "${indxname}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh Indexer and Wazuh Dashboard must be different."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -n "${winame}" ] && [ "${indxname}" == "${winame}" ]; then
        common_logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${dashname}" ] && [ "${winame}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh Server and Wazuh Indexer must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -z "$(echo "${server_node_names[@]}" | grep -w "${winame}")" ]; then
        common_logger -e "The Wazuh server node name ${winame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -z "$(echo "${indexer_node_names[@]}" | grep -w "${indxname}")" ]; then
        common_logger -e "The Wazuh Indexer node name ${indxname} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${dashname}" ] && [ -z "$(echo "${dashboard_node_names[@]}" | grep -w "${dashname}")" ]; then
        common_logger -e "The Wazuh Dashboard node name ${dashname} does not appear on the configuration file."
        exit 1
    fi

    if [[ "${dashname}" == -* ]] || [[ "${indxname}" == -* ]] || [[ "${winame}" == -* ]]; then
        common_logger -e "Node name cannot start with \"-\""
        exit 1
    fi

}

# This function checks if the target certificates are created before to start the installation.
function checks_previousCertificate() {
    if [ ! -f "${tar_file}" ]; then
        common_logger -e "Cannot find ${tar_file}. Run the script with the option -g|--generate-config-files to create it or copy it from another node."
        exit 1
    fi

    if [ -n "${indxname}" ]; then
        if [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${indxname}.pem)" ] || [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${indxname}-key.pem)" ]; then
            common_logger -e "There is no certificate for the indexer node ${indxname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${dashname}" ]; then
        if [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${dashname}.pem)" ] || [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${dashname}-key.pem)" ]; then
            common_logger -e "There is no certificate for the Wazuh Dashboard node ${dashname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${winame}" ]; then
        if [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${winame}.pem)" ] || [ -z "$(tar -tf ${tar_file} | egrep ^wazuh-install-files/${winame}-key.pem)" ]; then
            common_logger -e "There is no certificate for the wazuh server node ${winame} in ${tar_file}."
            exit 1
        fi
    fi
}

function checks_specifications() {

    cores=$(cat /proc/cpuinfo | grep -c processor )
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

}