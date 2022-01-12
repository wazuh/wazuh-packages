# Wazuh installer - checks.sh library. 
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function checkArch() {

    arch=$(uname -m)

    if [ "${arch}" != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

function checkArguments() {

    if ([ -n "${AIO}" ] || [ -n "$certificates" ]) && [ -f "${tar_file}" ]; then
            logger -e "File ${tar_file} exists. Please remove the certificates tar file if you want to create new certificates."
            exit 1
    fi

    if [ -n "${overwrite}" ] && [ -z "${AIO}" ] && [ -z "${elasticsearch}" ] && [ -z "${kibana}" ] && [ -z "${wazuh}" ]; then 
        logger -e "The argument -o|--overwrite can't be used by itself. If you want to uninstall the components use -u|--uninstall"
        exit 1
    fi

    if [ -n "${uninstall}" ]; then

        if [ -z "${wazuhinstalled}" ] && [ -z "${wazuh_remaining_files}" ]; then
            logger -w "Can't uninstall Wazuh manager. No components were found on the system."
        fi

        if [ -z "${filebeatinstalled}" ] && [ -z "${filebeat_remaining_files}" ]; then
            logger -w "Can't uninstall Filebeat. No components were found on the system."
        fi

        if [ -z "${elasticsearchinstalled}" ] && [ -z "${elastic_remaining_files}" ]; then
            logger -w "Can't uninstall Elasticsearch. No components were found on the system."
        fi

        if [ -z "${kibanainstalled}" ] && [ -z "${kibana_remaining_files}" ]; then
            logger -w "Can't uninstall. No components were found on the system."
        fi

        if [ -n "$AIO" ] || [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "The argument -u|--uninstall can't be used with -a, -k, -e or -w. If you want to overwrite the components use -o|--overwrite"
            exit 1
        fi
    fi

    if [ -n "${AIO}" ]; then

        if [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "Argument -a|--all-in-one is not compatible with -e|--elasticsearch, -k|--kibana or -w|--wazuh-server"
            exit 1
        fi

        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${elasticsearchinstalled}" ] || [ -n "${elastic_remaining_files}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ] || [ -n "${kibanainstalled}" ] || [ -n "${kibana_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack
            else
                logger -e "Some the Wazuh components were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
                exit 1
            fi
        fi
    fi

    if [ -n "${elasticsearch}" ]; then

        if [ -n "${elasticsearchinstalled}" ] || [ -n "${elastic_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack "elasticsearch"
            else 
                logger -e "Elasticsearch is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    if [ -n "${kibana}" ]; then
        if [ -n "${kibanainstalled}" ] || [ -n "${kibana_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack "kibana"
            else 
                logger -e "Kibana is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    if [ -n "${wazuh}" ]; then
        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack "wazuh"
            else 
                logger -e "Wazuh is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi

        if [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack "filebeat"
            else
                logger -e "Filebeat is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi
    if [ -n "${certificates}" ] && ([ -n "${AIO}" ] || [ -n "${elasticsearch}" ] || [ -n "${kibana}" ] || [ -n "${wazuh}" ] || [ -n "${development}" ] || [ -n "${overwrite}" ] || [ -n "${start_elastic_cluster}" ] || [ -n "${tar_conf}" ] || [ -n "${uninstall}" ]); then
            logger -e "The argument -c|--certificates can only be used by itself"
            exit 1
    fi

}

function checkHealth() {

    checkSpecs
    if [ -n "${elasticsearch}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for Elasticsearch done."
        fi
    fi
    if [ -n "${kibana}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for Kibana done."
        fi
    fi
    if [ -n "${wazuh}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 1700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for Wazuh Manager done."
        fi
    fi
    if [ -n "${aio}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for AIO done."
        fi
    fi

}

function checkIfInstalled() {

    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages | grep wazuh-manager | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi

    if [ -d "/var/ossec" ]; then
        wazuh_remaining_files=1
    fi

    if [ -n "${wazuhinstalled}" ]; then
        if [ "${sys_type}" == "zypper" ]; then
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $11}')
        else
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $2}')
        fi    
    fi

    if [ "${sys_type}" == "yum" ]; then
        elasticsearchinstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch | grep -v kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        elasticsearchinstalled=$(zypper packages | grep opendistroforelasticsearch | grep -v kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        elasticsearchinstalled=$(apt list --installed 2>/dev/null | grep opendistroforelasticsearch | grep -v kibana)
    fi

    if [ -d "/var/lib/elasticsearch/" ] || [ -d "/usr/share/elasticsearch" ] || [ -d "/etc/elasticsearch" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        elastic_remaining_files=1
    fi

    if [ -n "${elasticsearchinstalled}" ]; then
        if [ "${sys_type}" == "zypper" ]; then
            odversion=$(echo ${elasticsearchinstalled} | awk '{print $11}')
        else
            odversion=$(echo ${elasticsearchinstalled} | awk '{print $2}')
        fi
    fi

    if [ "${sys_type}" == "yum" ]; then
        filebeatinstalled=$(yum list installed 2>/dev/null | grep filebeat)
    elif [ "${sys_type}" == "zypper" ]; then
        filebeatinstalled=$(zypper packages | grep filebeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeatinstalled=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        filebeat_remaining_files=1
    fi

    if [ -n "${filebeatinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            filebeatversion=$(echo ${filebeatinstalled} | awk '{print $11}')
        else
            filebeatversion=$(echo ${filebeatinstalled} | awk '{print $2}')
        fi
    fi

    if [ "${sys_type}" == "yum" ]; then
        kibanainstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch-kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        kibanainstalled=$(zypper packages | grep opendistroforelasticsearch-kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        kibanainstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch-kibana)
    fi

    if [ -d "/var/lib/kibana/" ] || [ -d "/usr/share/kibana" ] || [ -d "/etc/kibana" ]; then
        kibana_remaining_files=1
    fi

    if [ -n "${kibanainstalled}" ]; then
        if [ "${sys_type}" == "zypper" ]; then
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $11}')
        else
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $2}')
        fi
    fi

}

# This function ensures different names in the config.yml file. 
function checkNames() {

    if [ -n "${einame}" ] && [ -n "${kiname}" ] && ([ "${einame}" == "${kiname}" ]); then
        logger -e "The node names for Elastisearch and Kibana must be different."
        exit 1
    fi

    if [ -n "${einame}" ] && [ -n "${winame}" ] && ([ "${einame}" == "${winame}" ]); then
        logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${kiname}" ] && ([ "${winame}" == "${kiname}" ]); then
        logger -e "The node names for Wazuh and Kibana must be different."
        exit 1
    fi

    all_node_names=("${elasticsearch_node_names[@]}" "${wazuh_servers_node_names[@]}" "${kibana_node_names[@]}")
    found=0
    for i in ${all_node_names[@]}; do
        if ([[ -n "${elasticsearch}" ]] && [[ "${i}" == "${einame}" ]]) || \
            ([[ -n "${wazuh}" ]] && [[ "${i}" == "${winame}" ]]) || \
            ([[ -n "${kibana}" ]] && [[ "${i}" == "${kiname}" ]]); then
            found=1
            break
        fi
    done
    if [[ $found -eq 0 ]]; then
        logger -e "The name given for the node does not appear on the configuration file."
        exit 1
    fi

}

# This function checks if the target certificates are created before to start the installation.
function checkPreviousCertificates() {

    if [ -n "${einame}" ]; then
        if [ -z "$(tar -tvf ${tar_file}|grep ${einame}.pem)" ] || [ -z "$(tar -tvf ${tar_file}|grep ${einame}-key.pem)" ]; then
            logger -e "There is no certificate for the elasticsearch node ${einame} in ${tar_file}."
            exit 1
        fi
    fi


    if [ -n "${kiname}" ]; then
        if [ -z "$(tar -tvf ${tar_file}|grep ${kiname}.pem)" ] || [ -z "$(tar -tvf ${tar_file}|grep ${kiname}-key.pem)" ]; then
            logger -e "There is no certificate for the kibana node ${kiname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${winame}" ]; then
        if [ -z "$(tar -tvf ${tar_file}|grep ${winame}.pem)" ] || [ -z "$(tar -tvf ${tar_file}|grep ${winame}-key.pem)" ]; then
            logger -e "There is no certificate for the wazuh server node ${winame} in ${tar_file}."
            exit 1
        fi
    fi

}

function checkSpecs() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

}

function checkSystem() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
    elif [ -n "$(command -v zypper)" ]; then
        sys_type="zypper"   
        sep="-"  
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"   
        sep="="
    else
        logger -e "Couldn't find type of system"
        exit 1
    fi

}
