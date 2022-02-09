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
readonly elasticsearch_oss_version="7.10.2"
readonly elasticsearch_basic_version="7.12.1"
readonly opendistro_version="1.13.2"
readonly opendistro_revision="1"
readonly wazuh_kibana_plugin_revision="1"
readonly wazuh_install_vesion="0.1"

## Links and paths to resources
readonly functions_path="install_functions/opendistro"
readonly config_path="config/opendistro"
readonly resources="https://packages-dev.wazuh.com/resources/${wazuh_major}"
readonly resources_functions="${resources}/${functions_path}"
readonly resources_config="${resources}/${config_path}"
readonly base_path="$(dirname $(readlink -f "$0"))"
readonly config_file="${base_path}/config.yml"
readonly tar_file="${base_path}/configurations.tar"

## JAVA_HOME
export JAVA_HOME=/usr/share/elasticsearch/jdk/

## Debug variable used during the installation
readonly logfile="/var/log/wazuh-unattended-installation.log"
debug=">> ${logfile} 2>&1"

trap cleanExit SIGINT

function cleanExit() {

    rollback_conf=""

    if [ -n "$spin_pid" ]; then
        eval "kill -9 $spin_pid ${debug}"
    fi

    until [[ "${rollback_conf}" =~ ^[N|Y|n|y]$ ]]; do
        echo -ne "\nDo you want to clean the ongoing installation?[Y/N]"
        read -r rollback_conf
    done
    if [[ "${rollback_conf}" =~ [N|n] ]]; then
        exit 1
    else
        rollBack
        exit 1
    fi

}

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -e <elasticsearch-node-name> | -k <kibana-node-name> | -s | -w <wazuh-node-name>"
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
    echo -e "        -e,  --elasticsearch [elasticsearch-node-name]"
    echo -e "                Elasticsearch installation."
    echo -e ""
    echo -e "        -f,  --fileconfig [path-to-config-yml]"
    echo -e "                Path to config file. By default: ${base_path}/config.yml"
    echo -e ""
    echo -e "        -F,  --force-kibana"
    echo -e "                Ignore Elasticsearch cluster related errors in kibana installation"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -k,  --kibana [kibana-node-name]"
    echo -e "                Kibana installation."
    echo -e ""
    echo -e "        -l,  --local"
    echo -e "                Use local files."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Starts the Elasticsearch cluster."
    echo -e ""
    echo -e "        -t,  --tar [path-to-certs-tar]"
    echo -e "                Path to tar containing certificate files. By default: ${base_path}/configurations.tar"
    echo -e ""
    echo -e "        -u,  --uninstall [component-name]"
    echo -e "                Use 'all' for complete components uninstall, 'manager', 'elasticsearch' or 'kibana' for single component uninstall."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -w,  --wazuh-server [wazuh-node-name]"
    echo -e "                Wazuh server installation. It includes Filebeat."
    echo -e ""
    exit 1

}

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
            logger -e "Unable to find resource in path ${base_path}/${functions_path}/${1}."
            exit 1
        fi
    else
        if ( curl -f -so "/tmp/${1}" "${resources_functions}/${1}" ); then
            sed -i 's/main $@//' "/tmp/${1}"
            . "/tmp/${1}"
            rm -f "/tmp/${1}"
        elif [ -f "${base_path}/${functions_path}/${1}" ]; then
            logger -e "Unable to download resource ${resources_functions}/${1}. Local file detected in ${base_path}/${functions_path}/, you may want to use the -l option."
            rm -f "/tmp/${1}"
            exit 1
        else
            logger -e "Unable to find resource ${resources_functions}/${1}."
            rm -f "/tmp/${1}"
            exit 1
        fi
    fi

}

function logger() {
    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    disableHeader=
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
            echo "${now} ${mtype} ${message}" | tee -a ${logfile}
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
            "-e"|"--elasticsearch")
                if [ -z "${2}" ]; then
                    logger -e "Arguments contain errors. Probably missing <node-name> after -e|--elasticsearch."
                    getHelp
                    exit 1
                fi
                elasticsearch=1
                einame="${2}"
                shift 2
                ;;
            "-f"|"--fileconfig")
                if [ -z "${2}" ]; then
                    logger -e "Error on arguments. Probably missing <path-to-config-yml> after -f|--fileconfig"
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
            "-k"|"--kibana")
                if [ -z "${2}" ]; then
                    logger -e "Error on arguments. Probably missing <node-name> after -k|--kibana"
                    getHelp
                    exit 1
                fi
                kibana=1
                kiname="${2}"
                shift 2
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
                    logger -e "Error on arguments. Probably missing <path-to-certs-tar> after -t|--tar"
                    getHelp
                    exit 1
                fi
                tar_conf="1"
                tar_file="${2}"
                shift 2
                ;;
            "-u"|"--uninstall")
                if [ -z "${2}" ]; then
                    logger -e "Error on arguments. Probably missing <component-name> after -u|--uninstall."
                    getHelp
                    exit 1
                fi
                uninstall=1
                uninstall_component_name="${2}"
                shift 2
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug="2>&1 | tee -a ${logfile}"
                shift 1
                ;;
            "-w"|"--wazuh-server")
                if [ -z "${2}" ]; then
                    logger -e "Error on arguments. Probably missing <node-name> after -w|--wazuh-server"
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
        logger -e "This script must be run as root."
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

    checkTools

    if [ -z "${uninstall}" ]; then
        logger "Starting Wazuh unattended installer. Wazuh version: ${wazuh_version}. Wazuh installer version: ${wazuh_install_vesion}"
    fi

# -------------- Preliminary checks  --------------------------------

    checkArch
    checkSystem
    if [ -z "${uninstall}" ]; then
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            checkHealth
        fi
    fi
    if [ -n "${AIO}" ] ; then
        rm -f "${tar_file}"
    fi
    checkIfInstalled
    checkArguments

# -------------- Uninstall case  ------------------------------------

    if [ -n "${uninstall}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"
        logger "------------------------------------ Uninstall ------------------------------------"
        rollBack
        exit 0
    fi

# -------------- Prerequisites and Wazuh repo  ----------------------

    if [ -n "${AIO}" ] || [ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ]; then
        logger "---------------------------------- Dependencies -----------------------------------"
        installPrerequisites
        addWazuhrepo
    fi

# -------------- Preliminary steps  --------------------------------

    if [ -z "${configurations}" ] && [ -z "${AIO}" ]; then
        checkPreviousCertificates
    fi

# -------------- Configuration creation case  -----------------------

    # Creation certificate case: Only AIO and -c option can create certificates.
    if [ -n "${configurations}" ] || [ -n "${AIO}" ]; then
        logger "------------------------------- Configuration files -------------------------------"
        if [ -n "${configurations}" ]; then
            checkOpenSSL
        fi
        createCertificates
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            createClusterKey
        fi
        gen_file="${base_path}/certs/password_file.yml"
        generatePasswordFile
        # Using cat instead of simple cp because OpenSUSE unknown error.
        eval "cat '${config_file}' > '${base_path}/certs/config.yml'"
        eval "tar -zcf '${tar_file}' -C '${base_path}/certs/' . ${debug}"
        eval "rm -rf '${base_path}/certs' ${debug}"
        logger "Configuration files created: ${tar_file}"
    fi

    if [ -z "${configurations}" ]; then
        extractConfig
        readConfig
        rm -f "${config_file}"
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && ( -n "${elasticsearch}"  || -n "${kibana}" || -n "${wazuh}" )]]; then
        checkNames
    fi

# -------------- Elasticsearch or Start Elasticsearch cluster case---

    if [ -n "${elasticsearch}" ] || [ -n "${start_elastic_cluster}" ] ; then
        importFunction "elasticsearch.sh"
    fi

# -------------- Elasticsearch case  --------------------------------

    if [ -n "${elasticsearch}" ]; then
        logger "-------------------------- Open Distro for Elasticsearch --------------------------"
        installElasticsearch
        configureElasticsearch
        startService "elasticsearch"
        initializeElasticsearch
    fi

# -------------- Start Elasticsearch cluster case  ------------------

    if [ -n "${start_elastic_cluster}" ]; then
        startElasticsearchCluster
        changePasswords
    fi

# -------------- Kibana case  ---------------------------------------

    if [ -n "${kibana}" ]; then
        logger "------------------------------------- Kibana --------------------------------------"

        importFunction "kibana.sh"

        installKibana
        configureKibana
        changePasswords
        startService "kibana"
        initializeKibana

    fi

# -------------- Wazuh case  ---------------------------------------

    if [ -n "${wazuh}" ]; then
        logger "----------------------------------- Wazuh server ----------------------------------"

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"

        installWazuh
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            configureWazuhCluster
        fi
        startService "wazuh-manager"
        installFilebeat
        configureFilebeat
        changePasswords
        startService "filebeat"
    fi

# -------------- AIO case  ------------------------------------------

    if [ -n "${AIO}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"

        logger "-------------------------- Open Distro for Elasticsearch --------------------------"
        installElasticsearch
        configureElasticsearch
        startService "elasticsearch"
        initializeElasticsearch
        logger "-------------------------------------- Wazuh --------------------------------------"
        installWazuh
        startService "wazuh-manager"
        installFilebeat
        configureFilebeat
        startService "filebeat"
        logger "------------------------------------- Kibana --------------------------------------"
        installKibana
        configureKibana
        startService "kibana"
        changePasswords
        initializeKibanaAIO
    fi

# -------------------------------------------------------------------

    if [ -z "${configurations}" ]; then
        restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ]; then
        logger "Installation finished. You can find in ${tar_file} all the certificates created, as well as password_file.yml, with the passwords for all users and config.yml, with the nodes of all of the components and their ips."
    elif [ -n "${start_elastic_cluster}" ]; then
        logger "Elasticsearch cluster started."
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
