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

max_progressbar_length=70
progressbar_status=0

progressBar() {
    if [ -z "${buffer}" ]; then
        buffer=""
        lines=1
    fi

    if [ "$1" ]; then
        buffer="${buffer}$1\n"
    fi

    totalcolumns=$( tput cols )
    columns=$(echo $((totalcolumns<max_progressbar_length ? totalcolumns : max_progressbar_length)))
    columns=$(( $columns-6 ))
    cols_done=$(( ($progressbar_status*$columns) / $progressbar_total ))
    cols_empty=$(( $columns-$cols_done ))
    progresspercentage=$(( ($progressbar_status*100) / $progressbar_total ))

    tput el1
    for i in $(seq $lines)
    do
        tput cuu1
        tput el
    done
    printf "${buffer}"
    echo -ne "|"
    for i in $(seq $cols_done); do echo -n "▇"; done
    for i in $(seq $cols_empty); do echo -n " "; done
    printf "|%3.3s%%\n" ${progresspercentage}

    lines=$(echo -e "$buffer" | wc -l)
    IFS=$'\n'
    for line in $(echo -e "$buffer"); do 
        length=$(expr length "$line")
        while [[ $length -gt $totalcolumns ]]; do
            ((lines+=1))
            length=$(( length - totalcolumns ))
        done
    done

    if [ $distributed_installs -gt 1 ] && [ $progressbar_status -eq $progressbar_total ]; then
        buffer=""
        lines=1
        printf "${buffer}"
        echo -ne "|"
        for i in $(seq $cols_done); do echo -n "▇"; done
        for i in $(seq $cols_empty); do echo -n " "; done
        printf "|%3.3s%%\n" ${progresspercentage}
    fi
}

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
    finalmessage=$(echo "$now" "$mtype" "$message") 
    echo "$finalmessage" >> ${logfile}
    if [ -z "$debugEnabled" ] && [ "$1" != "-e" ]; then
        progressBar "$finalmessage"
    else 
        echo -e "$finalmessage"
    fi
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

    progressbar_total=0
    distributed_installs=0

    while [ -n "$1" ]
    do
        case "$1" in
            "-a"|"--all-in-one")
                AIO=1
                winame="wazuh"
                progressbar_total=14
                shift 1
                ;;
            "-w"|"--wazuh-server")
                wazuh=1
                progressbar_total=8
                ((distributed_installs++))
                winame=$2
                shift 2
                ;;
            "-e"|"--elasticsearch")
                elasticsearch=1
                progressbar_total=8
                ((distributed_installs++))
                einame=$2
                shift 2
                ;;
            "-k"|"--kibana")
                kibana=1
                progressbar_total=8
                ((distributed_installs++))
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
    checkSystem

    if [ -z ${AIO} ] && ([ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ]); then
        readConfig
        checknames
        installPrerequisites
        addWazuhrepo
    fi

    if [ -n "${certificates}" ] || [ -n "${AIO}" ]; then
        createCertificates
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            createClusterKey
        fi
    fi
    
    if [ -n "${elasticsearch}" ]; then

        importFunction "elasticsearch.sh"

        progressbar_status=0
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Elasticsearch."
            ((progressbar_status++))
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
        logger "Elasticsearch installed correctly"
        ((distributed_installs--))
    fi

    if [ -n "${kibana}" ]; then

        importFunction "kibana.sh"

        progressbar_status=0
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Kibana.."
            ((progressbar_status++))
        else
            healthCheck kibana
        fi
        checkSystem
        installPrerequisites
        addWazuhrepo
        installKibana
        configureKibana
        restoreWazuhrepo
        logger "Kibana installed correctly"
        ((distributed_installs--))
    fi

    if [ -n "${wazuh}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"

        progressbar_status=0
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for Wazuh manager."
            ((progressbar_status++))
        else
            healthCheck wazuh
        fi
        installWazuh
        if [ -n "${wazuh_servers_node_types[*]}" ]; then
            configureWazuhCluster
            ((progressbar_total++))
        fi

        startService "wazuh-manager"

        installFilebeat
        configureFilebeat
        restoreWazuhrepo
        logger "Wazuh installed correctly"
        ((distributed_installs--))
    fi

    if [ -n "${AIO}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored for AIO."
            ((progressbar_status++))
        else
            healthCheck AIO
        fi

        installPrerequisites
        addWazuhrepo
        installWazuh
        startService "wazuh-manager"
        installElasticsearch
        configureElasticsearchAIO
        installFilebeat
        configureFilebeatAIO
        installKibana
        configureKibanaAIO
        restoreWazuhrepo
        logger "Installation Finished"
    fi

    restoreWazuhrepo

}

main "$@"
