# Common functions for Wazuh installation assistant,
# wazuh-passwords-tool and wazuh-cert-tool
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function common_checkAptLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while fuser "${apt_lockfile}" >/dev/null 2>&1 && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using APT. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}

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

    if [ -z "${debugLogger}" ] || { [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ]; }; then
        if [ -z "${nolog}" ] && { [ "$EUID" -eq 0 ] || [[ "$(basename "$0")" =~ $cert_tool_script_name ]]; }; then
            printf "%s\n" "${now} ${mtype} ${message}" | tee -a ${logfile}
        else
            printf "%b\n" "${now} ${mtype} ${message}"
        fi
    fi

}

function common_checkRoot() {

    common_logger -d "Checking root permissions."
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi

    common_logger -d "Checking sudo package."
    if ! command -v sudo > /dev/null; then 
        common_logger -e "The sudo package is not installed and it is necessary for the installation."
        exit 1;
    fi
}

function common_checkInstalled() {

    common_logger -d "Checking Wazuh installation."
    wazuh_installed=""
    indexer_installed=""
    filebeat_installed=""
    dashboard_installed=""

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-manager --quiet && wazuh_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        if dpkg -l wazuh-manager 2>/dev/null | grep -q -E '^ii\s'; then
            wazuh_installed=1
        fi
    fi

    if [ -d "/var/ossec" ]; then
        common_logger -d "There are Wazuh remaining files."
        wazuh_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-indexer --quiet && indexer_installed=1"

    elif [ "${sys_type}" == "apt-get" ]; then
        if dpkg -l wazuh-indexer 2>/dev/null | grep -q -E '^ii\s'; then
            indexer_installed=1
        fi
    fi

    if [ -d "/var/lib/wazuh-indexer/" ] || [ -d "/usr/share/wazuh-indexer" ] || [ -d "/etc/wazuh-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        common_logger -d "There are Wazuh indexer remaining files."
        indexer_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q filebeat --quiet && filebeat_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        if dpkg -l filebeat 2>/dev/null | grep -q -E '^ii\s'; then
            filebeat_installed=1
        fi
    fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        common_logger -d "There are Filebeat remaining files."
        filebeat_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q wazuh-dashboard --quiet && dashboard_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        if dpkg -l wazuh-dashboard 2>/dev/null | grep -q -E '^ii\s'; then
            dashboard_installed=1
        fi
    fi

    if [ -d "/var/lib/wazuh-dashboard/" ] || [ -d "/usr/share/wazuh-dashboard" ] || [ -d "/etc/wazuh-dashboard" ] || [ -d "/run/wazuh-dashboard/" ]; then
        common_logger -d "There are Wazuh dashboard remaining files."
        dashboard_remaining_files=1
    fi

}

function common_checkSystem() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
        common_logger -d "YUM package manager will be used."
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"
        sep="="
        common_logger -d "APT package manager will be used."
    else
        common_logger -e "Couldn't find YUM or APT package manager. Try installing the one corresponding to your operating system and then, launch the installation assistant again."
        exit 1
    fi

}

function common_checkWazuhConfigYaml() {

    common_logger -d "Checking Wazuh YAML configuration file."
    filecorrect=$(cert_parseYaml "${config_file}" | grep -Ev '^#|^\s*$' | grep -Pzc "\A(\s*(nodes_indexer__name|nodes_indexer__ip|nodes_server__name|nodes_server__ip|nodes_server__node_type|nodes_dashboard__name|nodes_dashboard__ip)=.*?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The configuration file ${config_file} does not have a correct format."
        exit 1
    fi

}

# Retries even if the --retry-connrefused is not available
function common_curl() {

    if [ -n "${curl_has_connrefused}" ]; then
        eval "curl $@ --retry-connrefused"
        e_code="${PIPESTATUS[0]}"
    else
        retries=0
        eval "curl $@"
        e_code="${PIPESTATUS[0]}"
        while [ "${e_code}" -eq 7 ] && [ "${retries}" -ne 12 ]; do
            retries=$((retries+1))
            sleep 5
            eval "curl $@"
            e_code="${PIPESTATUS[0]}"
        done
    fi
    return "${e_code}"

}

function common_remove_gpg_key() {

    common_logger -d "Removing GPG key from system."
    if [ "${sys_type}" == "yum" ]; then
        if { rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Wazuh"; } >/dev/null ; then
            key=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Wazuh Signing Key" | awk '{print $1}' )
            rpm -e "${key}"
        else
            common_logger "Wazuh GPG key not found in the system"
            return 1
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        if [ -f "/usr/share/keyrings/wazuh.gpg" ]; then
            rm -rf "/usr/share/keyrings/wazuh.gpg" "${debug}"
        else
            common_logger "Wazuh GPG key not found in the system"
            return 1
        fi
    fi

}

function common_checkYumLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while [ -f "${yum_lockfile}" ] && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using YUM. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}
