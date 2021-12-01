#!/bin/bash

## Package vars
WAZUH_MAJOR="4.2"
WAZUH_VER="4.2.5"
WAZUH_REV="1"
ELK_VER="7.10.2"
ELKB_VER="7.12.1"
OD_VER="1.13.2"
OD_REV="1"
WAZUH_KIB_PLUG_REV="1"

## Links and paths to resources
functions_path="install_functions/opendistro"
config_path="config/opendistro"
resources="https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/resources/${WAZUH_MAJOR}"
resources_functions="${resources}/${functions_path}"
resources_config="${resources}/${config_path}"

## Show script usage
getHelp() {

    echo ""
    echo "Usage: $0 arguments"
    echo -e "\t-A   | --AllInOne                      All-In-One installation"
    echo -e "\t-w   | --wazuh                         Wazuh installation"
    echo -e "\t-e   | --elasticsearch                 Elasticsearch installation"
    echo -e "\t-k   | --kibana                        Kibana installation"
    echo -e "\t-c   | --create-certificates           Create certificates from instances.yml file"
    echo -e "\t-en  | --elastic-node-name             Name of the elastic node, used for distributed installations"
    echo -e "\t-wn  | --wazuh-node-name               Name of the wazuh node, used for distributed installations"

    echo -e "\t-wk  | --wazuh-key <wazuh-cluster-key> Use this option as well as a wazuh_cluster_config.yml configuration file to automatically configure the wazuh cluster when using a multi-node installation"
    echo -e "\t-v   | --verbose                       Shows the complete installation output"
    echo -e "\t-i   | --ignore-health-check           Ignores the health-check"
    echo -e "\t-l   | --local                         Use local files"
    echo -e "\t-h   | --help                          Shows help"
    exit 1 # Exit script after printing help

}

importFunction() {
    if [ -n "${local}" ]; then
        if [ -f ./$functions_path/$1 ]; then
            sed -i "s/main @//" ./$functions_path/$1
            . ./$functions_path/$1
            echo "main @">> ./$functions_path/$1
        else 
            error=1
        fi
    else
        curl -so /tmp/$1 $resources_functions/$1
        if [ $? = 0]; then
            sed -i "s/main @//" /tmp/$1
            . /tmp/$1
            rm -f /tmp/$1
        else
            error=1 
        fi
    fi
    if [ ${error} = 1 ]; then
        logger -e "Unable to find resource $1. Exiting"
        exit 1
    fi
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
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
                getHelp
        esac
    done

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
        importFunction "wazuh-passwords-tool.sh"        

        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."
        else
            healthCheck elasticsearch
            healthCheck kibana
            healthCheck wazuh
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
        changePasswords
    fi
}

main "$@"
