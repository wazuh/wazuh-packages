# Common functions for Wazuh installation assistant,
# wazuh-passwords-tool and wazuh-cert-tool
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function common_logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    nolog=
    if [ -n "${1}" ]; then
        while [ -n "${1}" ]; do
            case ${1} in
                "-e")
                    mtype="ERROR:"
                    shift 1
                    ;;
                "-w")
                    mtype="WARNING:"
                    shift 1
                    ;;
                "-d")
                    debugLogger=1
                    mtype="DEBUG:"
                    shift 1
                    ;;
                "-nl")
                    nolog=1
                    shift 1
                    ;;
                *)
                    message="${1}"
                    shift 1
                    ;;
            esac
        done
    fi

    if [ -z "${debugLogger}" ] || ( [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ] ); then
        if [ "$EUID" -eq 0 ] && [ -z "${nolog}" ]; then
            printf "${now} ${mtype} ${message}\n" | tee -a ${logfile}
        else
            printf "${now} ${mtype} ${message}\n"
        fi
    fi

}

function common_checkRoot() {

    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi

}

function common_checkInstalled() {

    wazuh_installed=""
    indexer_installed=""
    filebeat_installed=""
    dashboard_installed=""

    if [ "${sys_type}" == "yum" ]; then
        wazuh_installed=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuh_installed=$(zypper packages | grep wazuh-manager | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuh_installed=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi

    if [ -d "/var/ossec" ]; then
        wazuh_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        indexer_installed=$(yum list installed 2>/dev/null | grep wazuh-indexer)
    elif [ "${sys_type}" == "zypper" ]; then
        indexer_installed=$(zypper packages | grep wazuh-indexer | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        indexer_installed=$(apt list --installed 2>/dev/null | grep wazuh-indexer)
    fi

    if [ -d "/var/lib/wazuh-indexer/" ] || [ -d "/usr/share/wazuh-indexer" ] || [ -d "/etc/wazuh-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        indexer_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        filebeat_installed=$(yum list installed 2>/dev/null | grep filebeat)
    elif [ "${sys_type}" == "zypper" ]; then
        filebeat_installed=$(zypper packages | grep filebeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeat_installed=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        filebeat_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        dashboard_installed=$(yum list installed 2>/dev/null | grep wazuh-dashboard)
    elif [ "${sys_type}" == "zypper" ]; then
        dashboard_installed=$(zypper packages | grep wazuh-dashboard | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboard_installed=$(apt list --installed  2>/dev/null | grep wazuh-dashboard)
    fi

    if [ -d "/var/lib/wazuh-dashboard/" ] || [ -d "/usr/share/wazuh-dashboard" ] || [ -d "/etc/wazuh-dashboard" ] || [ -d "/run/wazuh-dashboard/" ]; then
        dashboard_remaining_files=1
    fi

}

function common_checkSystem() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
    elif [ -n "$(command -v zypper)" ]; then
        sys_type="zypper"
        sep="-"
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"
        sep="="
    else
        common_logger -e "Couldn'd find type of system"
        exit 1
    fi

}

function common_checkWazuhConfigYaml() {

    filecorrect=$(cert_parseYaml "${config_file}" | grep -Ev '^#|^\s*$' | grep -Pzc "\A(\s*(nodes_indexer__name|nodes_indexer__ip|nodes_server__name|nodes_server__ip|nodes_server__node_type|nodes_dashboard__name|nodes_dashboard__ip)=.*?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The configuration file ${config_file} does not have a correct format."
        exit 1
    fi

}
