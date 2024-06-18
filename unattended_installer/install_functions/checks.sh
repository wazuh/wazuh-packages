# Wazuh installer - checks.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function checks_arch() {

    common_logger -d "Checking system architecture."
    arch=$(uname -m)

    if [ "${arch}" != "x86_64" ]; then
        common_logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

function checks_arguments() {

    # -------------- Port option validation ---------------------

    if [ -n "${port_specified}" ]; then
        if [ -z "${AIO}" ] && [ -z "${dashboard}" ]; then
            common_logger -e "The argument -p|--port can only be used with -a|--all-in-one or -wd|--wazuh-dashboard."
            exit 1
        fi
    fi

    # -------------- Offline installation ---------------------

    if [ -n "${offline_install}" ]; then
        if [ -z "${AIO}" ] && [ -z "${dashboard}" ] && [ -z "${indexer}" ] && [ -z "${wazuh}" ]; then
            common_logger -e "The -of|--offline-installation option must be used with -a, -ws, -wi, or -wd."
            exit 1
        fi
    fi

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
            common_logger "Wazuh indexer not found in the system so it was not uninstalled."
        fi

        if [ -z "${dashboard_installed}" ] && [ -z "${dashboard_remaining_files}" ]; then
            common_logger "Wazuh dashboard not found in the system so it was not uninstalled."
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

        if  [ -z "${overwrite}" ] && { [ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ]; }; then
            common_logger -e "Wazuh manager already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${indexer_installed}" ] || [ -n "${indexer_remaining_files}" ]; };then
            common_logger -e "Wazuh indexer already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]; }; then
            common_logger -e "Wazuh dashboard already installed."
            installedComponent=1
        fi
        if [ -z "${overwrite}" ] && { [ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]; }; then
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
                common_logger -e "Wazuh indexer is already installed in this node or some of its files have not been removed. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh dashboard --------------------------------

    if [ -n "${dashboard}" ]; then
        if [ -n "${dashboard_installed}" ] || [ -n "${dashboard_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh dashboard is already installed in this node or some of its files have not been removed. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh ------------------------------------------

    if [ -n "${wazuh}" ]; then
        if [ -n "${wazuh_installed}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${filebeat_installed}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                installCommon_rollBack
            else
                common_logger -e "Wazuh server components (wazuh-manager and filebeat) are already installed in this node or some of their files have not been removed. Use option -o|--overwrite to overwrite all components."
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

# Checks if the --retry-connrefused is available in curl
function check_curlVersion() {

    common_logger -d "Checking curl tool version."
    # --retry-connrefused was added in 7.52.0
    curl_version=$(curl -V | head -n 1 | awk '{ print $2 }')
    if [ $(check_versions ${curl_version} 7.52.0) == "0" ]; then
        curl_has_connrefused=0
    fi

}

function check_dist() {
    common_logger -d "Checking system distribution."
    dist_detect
    if  [ "${DIST_NAME}" != "centos" ] && [ "${DIST_NAME}" != "rhel" ] &&
        [ "${DIST_NAME}" != "amzn" ]   && [ "${DIST_NAME}" != "ubuntu" ] && [ "${DIST_NAME}" != "rocky" ]; then
        notsupported=1
    fi
    if [ "${DIST_NAME}" == "centos" ] && { [ "${DIST_VER}" -ne "7" ] && [ "${DIST_VER}" -ne "8" ]; }; then
        notsupported=1
    fi
    if [ "${DIST_NAME}" == "rhel" ]; then
        if [ "${DIST_VER}" -ne "7" ] && [ "${DIST_VER}" -ne "8" ] && [ "${DIST_VER}" -ne "9" ]; then
            notsupported=1
        fi
        need_centos_repos=1 
    fi

    if [ "${DIST_NAME}" == "amzn" ]; then
        if  [ "${DIST_VER}" != "2" ] &&
            [ "${DIST_VER}" != "2023" ] &&
            [ "${DIST_VER}" != "2018.03" ]; then
            notsupported=1
        fi
        if [ "${DIST_VER}" -eq "2023" ]; then
            checks_specialDepsAL2023
        fi
    fi

    if [ "${DIST_NAME}" == "ubuntu" ]; then
        if  [ "${DIST_VER}" == "16" ] || [ "${DIST_VER}" == "18" ] ||
            [ "${DIST_VER}" == "20" ] || [ "${DIST_VER}" == "22" ] ||
            [ "${DIST_VER}" == "24" ]; then
            if [ "${DIST_SUBVER}" != "04" ]; then
                notsupported=1
            fi
        else
            notsupported=1
        fi
    fi

    if [ "${DIST_NAME}" == "rocky" ]; then
        if [ "${DIST_VER}" != "9" ] || [ "${DIST_SUBVER}" != "4" ]; then
            notsupported=1
        fi
    fi

    if [ -n "${notsupported}" ]; then
        common_logger "The recommended systems are: Red Hat Enterprise Linux 7, 8, 9; CentOS 7, 8; Amazon Linux 2; Ubuntu 16.04, 18.04, 20.04, 22.04."
        common_logger -w "The current system does not match with the list of recommended systems. The installation may not work properly."
    fi
    common_logger -d "Detected distribution name: ${DIST_NAME}"
    common_logger -d "Detected distribution version: ${DIST_VER}"

}

function checks_health() {

    checks_specifications

    common_logger -d "CPU cores detected: ${cores}"
    common_logger -d "Free RAM memory detected: ${ram_gb}"

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

    common_logger -d "Checking node names in the configuration file."
    if [ -n "${indxname}" ] && [ -n "${dashname}" ] && [ "${indxname}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh indexer and Wazuh dashboard must be different."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -n "${winame}" ] && [ "${indxname}" == "${winame}" ]; then
        common_logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${dashname}" ] && [ "${winame}" == "${dashname}" ]; then
        common_logger -e "The node names for Wazuh server and Wazuh indexer must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && ! echo "${server_node_names[@]}" | grep -w -q "${winame}"; then
        common_logger -e "The Wazuh server node name ${winame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${indxname}" ] && ! echo "${indexer_node_names[@]}" | grep -w -q "${indxname}"; then
        common_logger -e "The Wazuh indexer node name ${indxname} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${dashname}" ] && ! echo "${dashboard_node_names[@]}" | grep -w -q "${dashname}"; then
        common_logger -e "The Wazuh dashboard node name ${dashname} does not appear on the configuration file."
        exit 1
    fi

    if [[ "${dashname}" == -* ]] || [[ "${indxname}" == -* ]] || [[ "${winame}" == -* ]]; then
        common_logger -e "Node name cannot start with \"-\""
        exit 1
    fi

}

# This function checks if the target certificates are created before to start the installation.
function checks_previousCertificate() {
    common_logger -d "Checking previous certificate existence."
    if [ ! -f "${tar_file}" ]; then
        common_logger -e "Cannot find ${tar_file}. Run the script with the option -g|--generate-config-files to create it or copy it from another node."
        exit 1
    fi

    if [ -n "${indxname}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${indxname}".pem  || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${indxname}"-key.pem; then
            common_logger -e "There is no certificate for the indexer node ${indxname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${dashname}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${dashname}".pem || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${dashname}"-key.pem; then
            common_logger -e "There is no certificate for the Wazuh dashboard node ${dashname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${winame}" ]; then
        if ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${winame}".pem || ! tar -tf "${tar_file}" | grep -q -E ^wazuh-install-files/"${winame}"-key.pem; then
            common_logger -e "There is no certificate for the wazuh server node ${winame} in ${tar_file}."
            exit 1
        fi
    fi
}

# Manages the special dependencies in case of AL2023
function checks_specialDepsAL2023() {

    # Change curl for curl-minimal
    assistant_yum_dependencies=( "${assistant_yum_dependencies[@]/curl/curl-minimal}" )

    # In containers, coreutils is replaced for coreutils-single
    if [ -f "/.dockerenv" ]; then
        assistant_yum_dependencies=( "${assistant_yum_dependencies[@]/coreutils/coreutils-single}" )
    fi
}

function checks_specifications() {

    cores=$(grep -c processor /proc/cpuinfo)
    ram_gb=$(free -m | awk 'FNR == 2 {print $2}')

}

function checks_ports() {
    
    common_logger -d "Checking ports availability."
    used_port=0
    ports=("$@")

    checks_firewall "${ports[@]}"

    if command -v lsof > /dev/null; then
        port_command="lsof -sTCP:LISTEN  -i:"
    else
        common_logger -w "Cannot find lsof. Port checking will be skipped."
        return 1
    fi

    for i in "${!ports[@]}"; do
        if eval "${port_command}""${ports[i]}" > /dev/null; then
            used_port=1
            common_logger -e "Port ${ports[i]} is being used by another process. Please, check it before installing Wazuh."
        fi
    done

    if [ "${used_port}" -eq 1 ]; then
        common_logger "The installation can not continue due to port usage by other processes."
        installCommon_rollBack
        exit 1
    fi

}

# Checks if the first version is greater equal than to second one
function check_versions() {

    if test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"; then
        echo 0
    else
        echo 1
    fi
}

function checks_available_port() {
    chosen_port="$1"
    shift
    ports_list=("$@")

    if [ "$chosen_port" -ne "${http_port}" ]; then
        for port in "${ports_list[@]}"; do
            if [ "$chosen_port" -eq "$port" ]; then
                common_logger -e "Port ${chosen_port} is reserved by Wazuh. Please, choose another port."
                exit 1
            fi
        done
    fi
}

function checks_firewall(){
    ports_list=("$@")
    f_ports=""
    f_message="The system has firewall enabled. Please ensure that traffic is allowed on "
    firewalld_installed=0
    ufw_installed=0


    # Record of the ports that must be exposed according to the installation
    if [ -n "${AIO}" ]; then
        f_message+="these ports: 1515, 1514, ${http_port}"
    elif [ -n "${dashboard}" ]; then
        f_message+="this port: ${http_port}"
    else
        f_message+="these ports:"
        for port in "${ports_list[@]}"; do
            f_message+=" ${port},"
        done

        # Deletes last comma
        f_message="${f_message%,}"
    fi

    # Check if the firewall is installed
    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q firewalld --quiet && firewalld_installed=1"
        eval "rpm -q ufw --quiet && ufw_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        if dpkg -l "firewalld" 2>/dev/null | grep -q -E '^ii\s'; then
            firewalld_installed=1
        fi
        if dpkg -l "ufw" 2>/dev/null | grep -q -E '^ii\s'; then
            ufw_installed=1
        fi
    fi

    # Check if the firewall is running
    if [ "${firewalld_installed}" == "1" ]; then
        if firewall-cmd --state 2>/dev/null | grep -q -w "running"; then
            common_logger -w "${f_message/firewall/Firewalld}."
        fi
    fi
    if [ "${ufw_installed}" == "1" ]; then
        if ufw status 2>/dev/null | grep -q -w "active"; then
            common_logger -w "${f_message/firewall/UFW}."
        fi
    fi

}
