#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -s | -wi <indexer-node-name> | -wd <dashboards-node-name> | -ws <wazuh-node-name>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                All-In-One installation."
    echo -e ""
    echo -e "        -c,  --create-configurations"
    echo -e "                Creates configurations.tar file containing config.yml, certificates, passwords and cluster key."
    echo -e ""
    echo -e "        -d,  --development"
    echo -e "                Uses development repository."
    echo -e ""
    echo -e "        -ds,  --disable-spinner"
    echo -e "                Disables the spinner indicator."
    echo -e ""
    echo -e ""
    echo -e "        -f,  --fileconfig <path-to-config-yml>"
    echo -e "                Path to config file. By default: ${base_path}/config.yml"
    echo -e ""
    echo -e "        -F,  --force-dashboard"
    echo -e "                Ignore indexer cluster related errors in Wazuh Dashboard installation"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Starts the indexer cluster."
    echo -e ""
    echo -e "        -t,  --tar <path-to-certs-tar>"
    echo -e "                Path to tar containing certificate files. By default: ${base_path}/configurations.tar"
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstalls all Wazuh components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboards <dashboards-node-name>"
    echo -e "                Wazuh dashboards installation."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer <indexer-node-name>"
    echo -e "                Wazuh indexer installation."
    echo -e ""
    echo -e "        -ws,  --wazuh-server <wazuh-node-name>"
    echo -e "                Wazuh server installation. It includes Filebeat."
    exit 1

}


function main() {

    if [ -z "${1}" ]; then
        common_getHelp
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
                    common_getHelp
                    exit 1
                fi
                config_file="${2}"
                shift 2
                ;;
            "-F"|"--force-dashboard")
                force=1
                shift 1
                ;;
            "-h"|"--help")
                common_getHelp
                ;;
            "-i"|"--ignore-health-check")
                ignore=1
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
                    common_getHelp
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
            "-wd"|"--wazuh-dashboard")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -wd|---wazuh-dashboard"
                    common_getHelp
                    exit 1
                fi
                dashboard=1
                dashname="${2}"
                shift 2
                ;;
            "-wi"|"--wazuh-indexer")
                if [ -z "${2}" ]; then
                    common_logger -e "Arguments contain errors. Probably missing <node-name> after -wi|--wazuh-indexer."
                    common_getHelp
                    exit 1
                fi
                indexer=1
                indxname="${2}"
                shift 2
                ;;
            "-ws"|"--wazuh-server")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -w|--wazuh-server"
                    common_getHelp
                    exit 1
                fi
                wazuh=1
                winame="${2}"
                shift 2
                ;;
            *)
                echo "Unknow option: "${1}""
                common_getHelp
        esac

        # This assignment will be present during all testing stages.
        # It must be removed when the unattended installer is published.
        development=1
    done

    if [ "${EUID}" -ne 0 ]; then
        common_logger -e "This script must be run as root."
        exit 1
    fi


    if [ -n "${development}" ]; then
        repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"
        repobaseurl="https://packages-dev.wazuh.com/pre-release"
        reporelease="unstable"
        filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"
    fi

    if [ -z "${disableSpinner}" ]; then
        common_spin &
        spin_pid=$!
        trap "kill -9 ${spin_pid} ${debug}" EXIT
    fi

    common_logger "Starting Wazuh unattended installer. Wazuh version: ${wazuh_version}. Wazuh installer version: ${wazuh_install_vesion}"

# -------------- Uninstall case  ------------------------------------

    common_checkSystem
    common_checkInstalled
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
            cert_checkOpenSSL
        fi
        common_createCertificates
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            common_createClusterKey
        fi
        gen_file="${base_path}/certs/password_file.yml"
        passwords_generatePasswordFile
        # Using cat instead of simple cp because OpenSUSE unknown error.
        eval "cat '${config_file}' > function common_getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -s | -wi <indexer-node-name> | -wd <dashboards-node-name> | -ws <wazuh-node-name>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                All-In-One installation."
    echo -e ""
    echo -e "        -c,  --create-configurations"
    echo -e "                Creates configurations.tar file containing config.yml, certificates, passwords and cluster key."
    echo -e ""
    echo -e "        -d,  --development"
    echo -e "                Uses development repository."
    echo -e ""
    echo -e "        -ds,  --disable-spinner"
    echo -e "                Disables the spinner indicator."
    echo -e ""
    echo -e ""
    echo -e "        -f,  --fileconfig <path-to-config-yml>"
    echo -e "                Path to config file. By default: ${base_path}/config.yml"
    echo -e ""
    echo -e "        -F,  --force-dashboard"
    echo -e "                Ignore indexer cluster related errors in Wazuh Dashboard installation"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Starts the indexer cluster."
    echo -e ""
    echo -e "        -t,  --tar <path-to-certs-tar>"
    echo -e "                Path to tar containing certificate files. By default: ${base_path}/configurations.tar"
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstalls all Wazuh components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboards <dashboards-node-name>"
    echo -e "                Wazuh dashboards installation."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer <indexer-node-name>"
    echo -e "                Wazuh indexer installation."
    echo -e ""
    echo -e "        -ws,  --wazuh-server <wazuh-node-name>"
    echo -e "                Wazuh server installation. It includes Filebeat."
    exit 1

}'${base_path}/certs/config.yml'"
        eval "tar -zcf '${tar_file}' -C '${base_path}/certs/' . ${debug}"
        eval "rm -rf '${base_path}/certs' ${debug}"
        common_logger "Configuration files created: ${tar_file}"
    fi

    if [ -z "${configurations}" ]; then
        common_extractConfig
        cert_readConfig
        rm -f "${config_file}"
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && ( -n "${indexer}"  || -n "${dashboard}" || -n "${wazuh}" )]]; then
        checks_names
    fi

# -------------- Prerequisites and Wazuh repo  ----------------------
    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        common_logger "------------------------------------ Dependencies -------------------------------------"
        common_installPrerequisites
        common_addWazuhRepo
    fi

# -------------- Wazuh Indexer case -------------------------------

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

# -------------- Wazuh Dashboard case  ------------------------------

    if [ -n "${dashboard}" ]; then
        common_logger "---------------------------------- Wazuh dashboard -----------------------------------"

        dashboard_install
        dashboard_configure
        common_changePasswords
        common_startService "wazuh-dashboard"
        dashboard_initialize

    fi

# -------------- Wazuh case  ---------------------------------------

    if [ -n "${wazuh}" ]; then
        common_logger "------------------------------------- Wazuh server ------------------------------------"

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
        common_logger "---------------------------------- Wazuh dashboard -----------------------------------"
        dashboard_install
        dashboard_configure
        common_startService "wazuh-dashboard"
        common_changePasswords
        dashboard_initializeAIO
    fi

# -------------------------------------------------------------------

    if [ -z "${configurations}" ]; then
        common_restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        common_logger "Installation finished. You can find in ${tar_file} all the certificates created, as well as password_file.yml, with the passwords for all users and config.yml, with the nodes of all of the components and their ips."
    elif [ -n "${start_elastic_cluster}" ]; then
        common_logger "Elasticsearch cluster started."
    fi

}
