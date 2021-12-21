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

## Debug variable used during the installation
logfile="/var/log/wazuh-unattended-installation.log"
debug=">> ${logfile} 2>&1"

getHelp() {

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
    echo -e "        -w,  --wazuh-server <wazuh-node-name>"
    echo -e "                Wazuh server installation. It includes Filebeat."
    echo -e ""
    echo -e "        -e,  --elasticsearch <elasticsearch-node-name>"
    echo -e "                Elasticsearch installation."
    echo -e ""
    echo -e "        -k,  --kibana"
    echo -e "                Kibana installation."
    echo -e ""
    echo -e "        -c,  --create-certificates"
    echo -e "                Create certificates from config.yml file."
    echo -e ""
    echo -e "        -wk, --wazuh-key <wazuh-cluster-key>"
    echo -e "                Use this option as well as a wazuh_cluster_config.yml configuration file to automatically configure the wazuh cluster when using a multi-node installation."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -l,  --local"
    echo -e "                Use local files."
    echo -e ""
    echo -e "        -d,  --development"
    echo -e "                Use development repository."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    exit 1 # Exit script after printing help

}

logger() {

    now=$(date +'%m/%d/%Y %H:%M:%S')
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

importFunction() {
    if [ -n "${local}" ]; then
        if [ -f ${base_path}/$functions_path/$1 ]; then
            cat ${base_path}/$functions_path/$1 |grep 'main $@' > /dev/null 2>&1
            has_main=$?
            if [ $has_main = 0 ]; then
                sed -i 's/main $@//' ${base_path}/$functions_path/$1
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
            sed -i 's/main $@//' /tmp/$1
            . /tmp/$1
            rm -f /tmp/$1
        else
            error=1 
        fi
    fi
    if [ "${error}" = "1" ]; then
        logger -e "Unable to find resource $1. Exiting."
        exit 1
    fi
}

main() {
    if [ ! -n  "$1" ]; then
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
                wazuh=1
                winame=$2
                shift 2
                ;;
            "-e"|"--elasticsearch")
                elasticsearch=1
                einame=$2
                shift 2
                ;;
            "-k"|"--kibana")
                kibana=1
                shift 1
                ;;
            "-c"|"--create-certificates")
                certificates=1
                shift 1
                ;;
            "-i"|"--ignore-health-check")
                ignore=1
                shift 1
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug='2>&1 | tee -a /var/log/wazuh-unattended-installation.log'
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
            "-h"|"--help")
                getHelp
                ;;
            *)
                echo "Unknow option: $1"
                getHelp
        esac
    done

    if [ "$EUID" -ne 0 ]; then
        logger -e "Error: This script must be run as root."
        exit 1;
    fi   

    importFunction "common.sh"
    importFunction "wazuh-cert-tool.sh"

    checkArch

    if [ -n "${certificates}" ] || [ -n "${AIO}" ]; then
        createCertificates
    fi
    
    checkSystem
    installPrerequisites
    addWazuhrepo

    if [ -z ${AIO} ]; then
        readConfig
        checkSystem
        installPrerequisites
        addWazuhrepo
    fi

    if [ -n "${elasticsearch}" ]; then

        importFunction "elasticsearch.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Elasticsearch."
        else
            healthCheck elasticsearch
        fi
        installElasticsearch 
        configureElasticsearch
    fi

    if [ -n "${kibana}" ]; then

        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Kibana."
        else
            healthCheck kibana
        fi
        installKibana 
        configureKibana
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
        if [ "${wazuh_cluster_config_enabled}" == "yes" ]; then
            configureWazuhCluster 
        fi  
        installFilebeat  
        configureFilebeat
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
        installWazuh
        installElasticsearch
        configureElasticsearchAIO
        installFilebeat
        configureFilebeatAIO
        installKibana
        configureKibanaAIO
    fi

    restoreWazuhrepo

}

main "$@"
