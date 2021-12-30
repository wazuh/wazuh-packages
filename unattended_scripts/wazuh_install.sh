#!/bin/bash

# Wazuh installer
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
wazuh_major="4.3"
wazuh_version="4.3.0"
wazuh_revision="1"
elasticsearch_oss_version="7.10.2"
elasticsearch_basic_version="7.12.1"
opendistro_version="1.13.2"
opendistro_revision="1"
wazuh_kibana_plugin_revision="1"

## Links and paths to resources
functions_path="install_functions/opendistro"
config_path="config/opendistro"
resources="https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/resources/${wazuh_major}"
resources_functions="${resources}/${functions_path}"
resources_config="${resources}/${config_path}"
base_path="$(dirname $(readlink -f $0))"

## JAVA_HOME
export JAVA_HOME=/usr/share/elasticsearch/jdk/

## Debug variable used during the installation
logfile="/var/log/wazuh-unattended-installation.log"
debug=">> ${logfile} 2>&1"

## More info to continue on
## https://stackoverflow.com/questions/3338030/multiple-bash-traps-for-the-same-signal
trap cleanExit SIGINT

function cleanExit() {

    if [ -n "$spin_pid" ]; then
        eval "kill -9 $spin_pid $debug"
    fi

    echo -e "\nDo you want to clean the ongoing installation?[Y/n]"
    read rollback_conf
    if [[ "$rollback_conf" =~ [N|n] ]]; then
        exit 1
    else 
        rollBack
        exit 1
    fi
}

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename $0) - Install and configure Wazuh All-In-One components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename $0) [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                All-In-One installation."
    echo -e ""
    echo -e "        -c,  --create-certificates"
    echo -e "                Create certificates from config.yml file."
    echo -e ""
    echo -e "        -d,  --development"
    echo -e "                Use development repository."
    echo -e ""
    echo -e "        -e,  --elasticsearch <elasticsearch-node-name>"
    echo -e "                Elasticsearch installation."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -k,  --kibana <kibana-node-name>"
    echo -e "                Kibana installation."
    echo -e ""
    echo -e "        -l,  --local"
    echo -e "                Use local files."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrite previously installed components of the stack. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Start the Elasticsearch cluster."
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstall all wazuh components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -w,  --wazuh-server <wazuh-node-name>"
    echo -e "                Wazuh server installation. It includes Filebeat."
    echo -e ""
    exit 1 
}

function spin() {
    trap "{ tput el1; exit 0; }" 15
    spinner="/|\\-/|\\-"
    trap "echo ''" EXIT
    while :
    do
        for i in `seq 0 7`
        do
            echo -n "${spinner:$i:1}"
            echo -en "\010"
            sleep 0.1
        done
    done
}

function logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    case $1 in 
        "-e")
            mtype="ERROR:"
            message="$2"
            ;;
        "-w")
            mtype="WARNING:"
            message="$2"
            ;;
        *)
            mtype="INFO:"
            message="$1"
            ;;
    esac
    echo $now $mtype $message | tee -a ${logfile}
}

function importFunction() {
    if [ -n "${local}" ]; then
        if [ -f ${base_path}/$functions_path/$1 ]; then
            cat ${base_path}/$functions_path/$1 |grep 'main $@' > /dev/null 2>&1
            has_main=$?
            if [ $has_main = 0 ]; then
                sed -i 's/main $@//' ${base_path}/$functions_path/$1
                sed -i '$ d' ${base_path}/$functions_path/$1
            fi
            . ${base_path}/$functions_path/$1
            if [ $has_main = 0 ]; then
                echo 'main $@' >> ${base_path}/$functions_path/$1
            fi
        else 
            error=1
        fi
    else
        curl -so /tmp/$1 $resources_functions/$1
        if [ $? = 0 ]; then
            checkContent=$(grep '<?xml version="1.0" encoding="UTF-8"?>' ${base_path}/$1)
                if [[ -n "${checkContent}" ]]; then
                    error=1
                    rm -f /tmp/$1
                else
                    sed -i 's/main $@//' /tmp/$1
                    . /tmp/$1
                    rm -f /tmp/$1
                fi
        else
            error=1
        fi
    fi
    if [ "${error}" = "1" ]; then
        logger -e "Unable to find resource $1. Exiting."
        exit 1
    fi
}

function main() {

    if [ ! -n "$1" ]; then
        getHelp
    fi

    while [ -n "$1" ]
    do
        case "$1" in
            "-a"|"--all-in-one")
                AIO=1
                shift 1
                ;;
            "-w"|"--wazuh-server")
                if [ -z "$2" ]; then
                    logger -e "Error on arguments. Probably missing <node-name> after -w|--wazuh-server"
                    getHelp
                    exit 1
                fi
                wazuh=1
                winame=$2
                shift 2
                ;;
            "-e"|"--elasticsearch")
                if [ -z "$2" ]; then
                    logger -e "Error on arguments. Probably missing <node-name> after -e|--elasticsearch"
                    getHelp
                    exit 1
                fi
                elasticsearch=1
                einame=$2
                shift 2
                ;;
            "-k"|"--kibana")
                if [ -z "$2" ]; then
                    logger -e "Error on arguments. Probably missing <node-name> after -k|--kibana"
                    getHelp
                    exit 1
                fi
                kibana=1
                kiname=$2
                shift 2
                ;;
            "-c"|"--create-certificates")
                certificates=1
                shift 1
                ;;
            "-s"|"--start-cluster")
                start_elastic_cluster=1
                shift 1
                ;;
            "-i"|"--ignore-health-check")
                ignore=1
                shift 1
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug="2>&1 | tee -a ${logfile}"
                shift 1
                ;;
            "-d"|"--development")
                development=1
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
            "-u"|"--uninstall")
                uninstall=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                echo "Unknow option: $1"
                getHelp
        esac
    done

    spin &
    spin_pid=$!
    trap "kill -9 $spin_pid $debug" EXIT

    if [ "$EUID" -ne 0 ]; then
        logger -e "Error: This script must be run as root."
        exit 1
    fi

    importFunction "common.sh"
    importFunction "wazuh-cert-tool.sh"
    importFunction "wazuh-passwords-tool.sh"
            
    checkArch
    checkSystem
    checkInstalled
    checkArguments
    readConfig

    if [ -n "${uninstall}" ]; then
        logger "Removing all installed components."
        rollBack
        exit 0
    fi
    
    if [ -z "${AIO}" ] && ([ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ]); then
        checkNames
    fi

    if [ -n "${certificates}" ] || [ -n "${AIO}" ]; then
        checkOpenSSL
        createCertificates
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            createClusterKey
        fi
        gen_file="${base_path}/certs/password_file.yml"
        generatePasswordFile 
        sudo tar -zcf certs.tar -C certs/ .
        rm -rf "${base_path}/certs"
    fi

    if [ -n "${AIO}" ] || [ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ]; then

        if [ ! -f ${base_path}/certs.tar ]; then
            logger -e "No certificates file found (${base_path}/certs.tar). Run the script with the option -c|--certificates to create automatically or copy them from the node where they were created."
            exit 1
        fi

        if [ -d ${base_path}/certs ]; then
            checkPreviousCertificates
        fi

        installPrerequisites
        addWazuhrepo
    fi

    if [ -n "${elasticsearch}" ]; then

        if [ ! -f "${base_path}/certs.tar" ]; then
            logger -e "Certificates not found. Exiting"
            exit 1
        fi

        importFunction "elasticsearch.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Elasticsearch."
        else
            healthCheck elasticsearch
        fi

        installElasticsearch 
        configureElasticsearch
        startService "elasticsearch"
        initializeElasticsearch
        changePasswords
    fi

    if [ -n "${start_elastic_cluster}" ]; then
        importFunction "elasticsearch.sh"
        startElasticsearchCluster
    fi

    if [ -n "${kibana}" ]; then

        if [ ! -f "${base_path}/certs.tar" ]; then
            logger -e "Certificates not found. Exiting"
            exit 1
        fi

        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Kibana."
        else
            healthCheck kibana
        fi

        installKibana 
        configureKibana
        changePasswords
        startService "kibana"
        initializeKibana

    fi

    if [ -n "${wazuh}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Wazuh manager."
        else
            healthCheck wazuh
        fi
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

    if [ -n "${AIO}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for AIO."
        else
            healthCheck AIO
        fi

        installElasticsearch
        configureElasticsearchAIO
        startService "elasticsearch"
        initializeElasticsearch
        installWazuh
        startService "wazuh-manager"
        installFilebeat
        configureFilebeatAIO
        startService "filebeat"
        installKibana
        configureKibanaAIO
        startService "kibana"
        changePasswords
        initializeKibanaAIO
    fi

    restoreWazuhrepo

    if [ -n "${AIO}" ] || [ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}"  ]; then
        logger "Installation finished."
    elif [ -n "${start_elastic_cluster}" ]; then
        logger "Elasticsearch cluster started."
    fi

}

main $@
