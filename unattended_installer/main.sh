#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly wazuh_major="4.3"
readonly wazuh_version="4.3.0"
readonly wazuh_revision="1"
readonly filebeat_version="7.10.2"
readonly opendistro_version="1.13.2"
readonly opendistro_revision="1"
readonly wazuh_install_vesion="0.1"

## Links and paths to resources
readonly functions_path="install_functions"
readonly config_path="config"
readonly resources="https://packages-dev.wazuh.com/resources/${wazuh_major}"
readonly resources_functions="${resources}/${functions_path}"
readonly resources_config="${resources}/${config_path}"
readonly base_path="$(dirname $(readlink -f "$0"))"
readonly config_file="${base_path}/config.yml"
readonly tar_file="${base_path}/configurations.tar"

## JAVA_HOME
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/

## Debug variable used during the installation
readonly logfile="/var/log/wazuh-unattended-installation.log"
debug=">> ${logfile} 2>&1"

trap common_cleanExit SIGINT

function importFunction() {

    if [ -n "${local}" ]; then
        if [ -f "${base_path}/${functions_path}/${1}" ]; then
            cat "${base_path}/${functions_path}/${1}" | grep 'main $@' > /dev/null 2>&1
            has_main=$?

            if [ $has_main = 0 ]; then
                sed -i 's/main $@//' "${base_path}/${functions_path}/${1}"
                sed -i '$ d' "${base_path}/${functions_path}/${1}"
            fi
            # Loading functions
            . "${base_path}/${functions_path}/${1}"

            if [ $has_main = 0 ]; then
                echo 'main $@' >> "${base_path}/${functions_path}/${1}"
            fi
        else
            common_logger -e "Unable to find resource in path ${base_path}/${functions_path}/${1}."
            exit 1
        fi
    else
        if ( curl -f -so "/tmp/${1}" "${resources_functions}/${1}" ); then
            sed -i 's/main $@//' "/tmp/${1}"
            . "/tmp/${1}"
            rm -f "/tmp/${1}"
        elif [ -f "${base_path}/${functions_path}/${1}" ]; then
            common_logger -e "Unable to download resource ${resources_functions}/${1}. Local file detected in ${base_path}/${functions_path}/, you may want to use the -l option."
            rm -f "/tmp/${1}"
            exit 1
        else
            common_logger -e "Unable to find resource ${resources_functions}/${1}."
            rm -f "/tmp/${1}"
            exit 1
        fi
    fi

}

function main() {

    if [ -z "${1}" ]; then
        getHelp
    fi

    while [ -n "${1}" ]
    do
        case "${1}" in
            "-a"|"--all-in-one")
                AIO=1
                shift 1
                ;;
            "-c"|"--create-configurations")
                configurations=1
                shift 1
                ;;
            "-d"|"--development")
                development=1
                shift 1
                ;;
            "-ds"|"--disable-spinner")
                disableSpinner=1
                shift 1
                ;;
            "-f"|"--fileconfig")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-config-yml> after -f|--fileconfig"
                    getHelp
                    exit 1
                fi
                config_file="${2}"
                shift 2
                ;;
            "-F"|"--force-kibana")
                force=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            "-i"|"--ignore-health-check")
                ignore=1
                shift 1
                ;;
            "-l"|"--local")
                local=1
                shift 1
                ;;
            "-o"|"--overwrite")
                overwrite=1
                shift 1
                ;;
            "-s"|"--start-cluster")
                start_elastic_cluster=1
                shift 1
                ;;
            "-t"|"--tar")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-certs-tar> after -t|--tar"
                    getHelp
                    exit 1
                fi
                tar_conf="1"
                tar_file="${2}"
                shift 2
                ;;
            "-u"|"--uninstall")
                uninstall=1
                shift 1
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug="2>&1 | tee -a ${logfile}"
                shift 1
                ;;
            "-wd"|"--wazuh-dashboards")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -wd|---wazuh-dashboards"
                    getHelp
                    exit 1
                fi
                dashboards=1
                dashname="${2}"
                shift 2
                ;;
            "-wi"|"--wazuh-indexer")
                if [ -z "${2}" ]; then
                    common_logger -e "Arguments contain errors. Probably missing <node-name> after -wi|--wazuh-indexer."
                    getHelp
                    exit 1
                fi
                indexer=1
                indxname="${2}"
                shift 2
                ;;
            "-ws"|"--wazuh-server")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -w|--wazuh-server"
                    getHelp
                    exit 1
                fi
                wazuh=1
                winame="${2}"
                shift 2
                ;;
            *)
                echo "Unknow option: "${1}""
                getHelp
        esac

        # This assignment will be present during all testing stages.
        # It must be removed when the unattended installer is published.
        development=1
    done

    if [ "${EUID}" -ne 0 ]; then
        common_logger -e "This script must be run as root."
        exit 1
    fi

    if [ -z "${disableSpinner}" ]; then
        spin &
        spin_pid=$!
        trap "kill -9 ${spin_pid} ${debug}" EXIT
    fi

# -------------- Functions import -----------------------------------

    importFunction "checks.sh"
    importFunction "common.sh"
    importFunction "wazuh-cert-tool.sh"
    importFunction "wazuh-passwords-tool.sh"

    common_logger "Starting Wazuh unattended installer. Wazuh version: ${wazuh_version}. Wazuh installer version: ${wazuh_install_vesion}"

# -------------- Uninstall case  ------------------------------------

    checks_installed
    if [ -n "${uninstall}" ]; then
        common_logger "-------------------------------------- Uninstall --------------------------------------"
        common_logger "Removing all installed components."
        common_rollBack
        common_logger "All components removed."
        exit 0
    fi

# -------------- Preliminary checks  --------------------------------

    if [ -z "${configurations}" ] && [ -z "${AIO}" ]; then
        checks_previousCertificate
    fi
    checks_arch
    checks_system
    if [ -n "${ignore}" ]; then
        common_logger -w "Health-check ignored."
    else
        checks_health
    fi
    if [ -n "${AIO}" ] ; then
        rm -f "${tar_file}"
    fi
    checks_arguments

# -------------- Configuration creation case  -----------------------

    # Creation certificate case: Only AIO and -c option can create certificates.
    if [ -n "${configurations}" ] || [ -n "${AIO}" ]; then
        common_logger "--------------------------------- Configuration files ---------------------------------"
        if [ -n "${configurations}" ]; then
            checkOpenSSL
        fi
        common_createCertificates
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            common_createClusterKey
        fi
        gen_file="${base_path}/certs/password_file.yml"
        generatePasswordFile
        # Using cat instead of simple cp because OpenSUSE unknown error.
        eval "cat '${config_file}' > '${base_path}/certs/config.yml'"
        eval "tar -zcf '${tar_file}' -C '${base_path}/certs/' . ${debug}"
        eval "rm -rf '${base_path}/certs' ${debug}"
        common_logger "Configuration files created: ${tar_file}"
    fi

    if [ -z "${configurations}" ]; then
        common_extractConfig
        readConfig
        rm -f "${config_file}"
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && ( -n "${indexer}"  || -n "${dashboards}" || -n "${wazuh}" )]]; then
        checks_names
    fi

# -------------- Prerequisites and Wazuh repo  ----------------------
    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboards}" ] || [ -n "${wazuh}" ]; then
        common_logger "------------------------------------ Dependencies -------------------------------------"
        common_installPrerequisites
        common_addWazuhRepo
    fi
# -------------- Elasticsearch or Start Elasticsearch cluster case---

    if [ -n "${indexer}" ] || [ -n "${start_elastic_cluster}" ] ; then
        importFunction "indexer.sh"
    fi

# -------------- Elasticsearch case  --------------------------------

    if [ -n "${indexer}" ]; then
        common_logger "------------------------------------ Wazuh indexer ------------------------------------"
        indexer_install
        indexer_configure
        common_startService "wazuh-indexer"
        indexer_initialize
    fi

# -------------- Start Elasticsearch cluster case  ------------------

    if [ -n "${start_elastic_cluster}" ]; then
        indexer_startCluster
        common_changePasswords
    fi

# -------------- Kibana case  ---------------------------------------

    if [ -n "${dashboards}" ]; then
        common_logger "---------------------------------- Wazuh dashboards -----------------------------------"

        importFunction "dashboards.sh"

        dashboards_install
        dashboards_configure
        common_changePasswords
        common_startService "wazuh-dashboards"
        dashboards_initialize

    fi

# -------------- Wazuh case  ---------------------------------------

    if [ -n "${wazuh}" ]; then
        common_logger "------------------------------------- Wazuh server ------------------------------------"

        importFunction "manager.sh"
        importFunction "filebeat.sh"

        manager_install
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            manager_startCluster
        fi
        common_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        common_changePasswords
        common_startService "filebeat"
    fi

# -------------- AIO case  ------------------------------------------

    if [ -n "${AIO}" ]; then

        importFunction "manager.sh"
        importFunction "filebeat.sh"
        importFunction "indexer.sh"
        importFunction "dashboards.sh"

        common_logger "------------------------------------ Wazuh indexer ------------------------------------"
        indexer_install
        indexer_configure
        common_startService "wazuh-indexer"
        indexer_initialize
        common_logger "------------------------------------- Wazuh server ------------------------------------"
        manager_install
        common_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        common_startService "filebeat"
        common_logger "---------------------------------- Wazuh dashboards -----------------------------------"
        dashboards_install
        dashboards_configure
        common_startService "wazuh-dashboards"
        common_changePasswords
        dashboards_initializeAIO
    fi

# -------------------------------------------------------------------

    if [ -z "${configurations}" ]; then
        common_restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboards}" ] || [ -n "${wazuh}" ]; then
        common_logger "Installation finished. You can find in ${tar_file} all the certificates created, as well as password_file.yml, with the passwords for all users and config.yml, with the nodes of all of the components and their ips."
    elif [ -n "${start_elastic_cluster}" ]; then
        common_logger "Elasticsearch cluster started."
    fi

}

function spin() {

    trap "{ tput el1; exit 0; }" 15
    spinner="/|\\-/|\\-"
    trap "echo ''" EXIT
    while :
    do
        for i in $(seq 0 7)
        do
            echo -n "${spinner:$i:1}"
            echo -en "\010"
            sleep 0.1
        done
    done

}

main "$@"
