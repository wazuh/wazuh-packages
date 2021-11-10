#!/bin/bash

set -x

## Package vars
WAZUH_MAJOR="4.2"
WAZUH_VER="4.2.3"
WAZUH_REV="1"
ELK_VER="7.10.2"
ELKB_VER="7.12.1"
OD_VER="1.13.2"
OD_REV="1"
WAZUH_KIB_PLUG_REV="1"

## Links and paths to resources
functions_path="install_functions/opendistro"
config_path="config/opendistro"
resources="https://packages.wazuh.com/resources/${WAZUH_MAJOR}"
resources_functions="${resources}/${WAZUH_MAJOR}/${functions_path}"
resources_config="${resources}/{WAZUH_MAJOR}/${config_path}"

## Show script usage
getHelp() {

    echo ""
    echo "Usage: $0 arguments"
    echo -e "\t-A   | --AllInOne            All-In-One installation"
    echo -e "\t-w   | --wazuh               Wazuh installation"
    echo -e "\t-e   | --elasticsearch       Elasticsearch installation"
    echo -e "\t-k   | --kibana              Kibana installation"
    echo -e "\t-n   | --node-name           Name of the node, used for distributed installations"

    echo -e "\t-r   | --uninstall           Remove the installation"
    echo -e "\t-v   | --verbose             Shows the complete installation output"
    echo -e "\t-i   | --ignore-health-check Ignores the health-check"
    echo -e "\t-l   | --local               Use local files"
    echo -e "\t-h   | --help                Shows help"
    exit 1 # Exit script after printing help

}

importFunction() {
    if [ -n "${local}" ]; then
        . ./$functions_path/$1
    else
        curl -so /tmp/$1 $resources_functions/$1
        . /tmp/$1
    fi
}

main() {
    echo $1
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi   

    while [ -n "$1" ]
        do
            case "$1" in
            "-A"|"--AllInOne")
                AIO=1
                shift 1
            ;;
            "-w"|"--wazuh")
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
            "-n"|"--node-name")
                iname=$2
                shift
                shift
                ;;

            "-c"|"--create-certificates")
                certificates=1
                shift 1
                ;;
            "-i"|"--ignore-healthcheck")
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
            "-h"|"--help")
                getHelp
                ;;
            *)
                getHelp
            esac
        done

    importFunction "common.sh"
    if [ -n "${elastic}" ]; then

        importFunction "elasticsearch.sh"

        if [ -n "${ignore}" ]; then
            echo "Health-check ignored."
        else
            healthCheck elastic
        fi
        checkConfig
        installPrerequisites
        addWazuhrepo
        checkNodes
        installElasticsearch 
        configureElasticsearch iname
    fi

    if [ -n "${kibana}" ]; then

        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            echo "Health-check ignored."
        else
            healthCheck kibana
        fi
        checkConfig
        installPrerequisites
        addWazuhrepo
        installKibana 
        configureKibana iname
    fi

    if [ -n "${wazuh}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"

        if [ -n "${ignore}" ]; then
            echo "Health-check ignored."
        else
            healthCheck wazuh
        fi
        checkConfig
        installPrerequisites
        addWazuhrepo
        installWazuh
        configureWazuhtAIO
        installFilebeat iname
        configureFilebeat
    fi

    if [ -n "${AIO}" ]; then

        importFunction "wazuh.sh"
        importFunction "filebeat.sh"
        importFunction "elasticsearch.sh"
        importFunction "kibana.sh"

        if [ -n "${ignore}" ]; then
            echo "Health-check ignored."
        else
            healthCheck elasticsearch
            healthCheck kibana
            healthCheck wazuh
        fi
        checkConfig
        installPrerequisites
        addWazuhrepo
        installWazuh
        configureWazuhtAIO
        installFilebeat iname
        configureFilebeatAIO
    fi
}

main "$@"
