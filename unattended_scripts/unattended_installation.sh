#!/bin/bash

# Wazuh installer
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
wazuh_major="4.2"
wazuh_ver="4.2.5"
wazuh_rev="1"
elk_ver="7.10.2"
elkb_ver="7.12.1"
od_ver="1.13.2"
od_rev="1"
wazuh_kib_plug_rev="1"

## Links and paths to resources
functions_path="install_functions/opendistro"
config_path="config/opendistro"
resources="https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/resources/${wazuh_major}"
resources_functions="${resources}/${functions_path}"
resources_config="${resources}/${config_path}"

## Show script usage
getHelp() {

    echo ""
    echo "Usage: $(basename $0) options"
    echo -e "        -a,  --all-in-one"
    echo -e "                All-In-One installation."
    echo -e "        -w,  --wazuh-server"
    echo -e "                Wazuh server installation. It includes Filebeat."
    echo -e "        -e,  --elasticsearch"
    echo -e "                Elasticsearch installation."
    echo -e "        -k,  --kibana"
    echo -e "                Kibana installation."
    echo -e "        -c,  --create-certificates"
    echo -e "                Create certificates from instances.yml file."
    echo -e "        -en, --elastic-node-name"
    echo -e "                Name of the elastic node, used for distributed installations."
    echo -e "        -wn, --wazuh-node-name"
    echo -e "                Name of the wazuh node, used for distributed installations."

    echo -e "        -wk, --wazuh-key <wazuh-cluster-key>"
    echo -e "                Use this option as well as a wazuh_cluster_config.yml configuration file to automatically configure the wazuh cluster when using a multi-node installation."
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e "        -l,  --local"
    echo -e "                Use local files."
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    exit 1 # Exit script after printing help

}

importFunction() {
    if [ -n "${local}" ]; then
        . ./$functions_path/$1
    else
        curl -so /tmp/$1 $resources_functions/$1
        . /tmp/$1
        rm -f /tmp/$1
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
            "-d"|"--debug")
                debugEnabled=1
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
        echo "Error: This script must be run as root."
        exit 1;
    fi   

    importFunction "common.sh"
    importFunction "wazuh-cert-tool.sh"

    if [ -n "${certificates}" ] || [ -n "${AIO}" ]; then
        createCertificates
    fi

    if [ -n "${elastic}" ]; then

        importFunction "elasticsearch.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck elastic
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        checkNodes
        installElasticsearch 
        configureElasticsearch
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
    fi
}

main "$@"
