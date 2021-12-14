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
elastic_oss_version="7.10.2"
elastic_basic_version="7.12.1"
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
debug='>> /var/log/wazuh-unattended-installation.log 2>&1'

## Show script usage
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
    echo -e "        -w,  --wazuh-server"
    echo -e "                Wazuh server installation. It includes Filebeat."
    echo -e ""
    echo -e "        -e,  --elasticsearch"
    echo -e "                Elasticsearch installation."
    echo -e ""
    echo -e "        -k,  --kibana"
    echo -e "                Kibana installation."
    echo -e ""
    echo -e "        -c,  --create-certificates"
    echo -e "                Create certificates from instances.yml file."
    echo -e ""
    echo -e "        -en, --elastic-node-name"
    echo -e "                Name of the elastic node, used for distributed installations."
    echo -e ""
    echo -e "        -wn, --wazuh-node-name"
    echo -e "                Name of the wazuh node, used for distributed installations."
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
    echo -e "        -d,  --dev"
    echo -e "                Use development repository."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    exit 1 # Exit script after printing help

}

## Prints information
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
    echo $now $mtype $message | tee -a /var/log/wazuh-unattended-installation.log
}

importFunction() {
    if [ -n "${local}" ]; then
        if [ -f ${base_path}/$functions_path/$1 ]; then
            eval "sed -i '/main @/d' ${base_path}/$functions_path/$1 ${debug}"
            eval ". ${base_path}/$functions_path/$1"
            echo 'main @' >> ${base_path}/$functions_path/$1
        else 
            error=1
        fi
    else
        eval "curl -so /tmp/$1 $resources_functions/$1 ${debug}"
        if [[ $? == 0 ]]; then
            eval "sed -i '/main @/d' /tmp/$1 ${debug}"
            eval ". /tmp/$1 ${debug}"
            eval "rm -f /tmp/$1 ${debug}"
        else
            error=1 
        fi
    fi
    if [[ ${error} == 1 ]]; then
        logger -e "Unable to find resource $1. Exiting"
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
                shift 1
                ;;
            "-e"|"--elasticsearch")
                elastic=1
                shift 1
                ;;
            "-k"|"--kibana")
                kibana=1
                shift 1
                ;;
            "-en"|"--elastic-node-name")
                einame=$2
                shift 2
                ;;
            "-wn"|"--wazuh-node-name")
                winame=$2
                shift 2
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
            "-d"|"--dev")
                development=1
                shift 1
                ;;
            "-l"|"--local")
                local=1
                shift 1
                ;;
            "-wk"|"--wazuh-key")
                wazuh_config=1
                wazuhclusterkey="$2"
                shift 2
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
    logfile="/var/log/wazuh-unattended-installation.log"
    importFunction "wazuh-cert-tool.sh"

    checkArch
    
    if [ -n "${certificates}" ] || [ -n "${AIO}" ]; then
        createCertificates
    fi

    if [ -n "${elastic}" ]; then

        importFunction "elasticsearch.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck elasticsearch
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        checkNodes
        installElasticsearch 
        configureElasticsearch
        restoreWazuhrepo
    fi

    if [ -n "${kibana}" ]; then

        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck kibana
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        installKibana 
        configureKibana
        restoreWazuhrepo
    fi

    if [ -n "${wazuh}" ]; then

        if [ -n "$wazuhclusterkey" ] && [ ! -f wazuh_cluster_config.yml ]; then
            logger -e "No wazuh_cluster_config.yml file found."
            exit 1;
        fi

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck wazuh
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        installWazuh
        if [ -n "$wazuhclusterkey" ]; then
            configureWazuhCluster 
        fi  
        installFilebeat  
        configureFilebeat
        restoreWazuhrepo
    fi

    if [ -n "${AIO}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck AIO
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        installWazuh
        installElasticsearch
        configureElasticsearchAIO
        installFilebeat
        configureFilebeatAIO
        installKibana
        configureKibanaAIO
        restoreWazuhrepo
    fi
}

main "$@"
