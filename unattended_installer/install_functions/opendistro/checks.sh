# Wazuh installer - checks.sh functions.
# Copyright (C) 2015, Wazuh Inc.
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

    # -------------- Configurations ---------------------------------

    if [[ ( -n "${AIO}"  || -n "${configurations}" ) && -f "${tar_file}" ]]; then
        logger -e "File ${tar_file} exists. Please remove it if you want to use a new configuration."
        exit 1
    fi

    if [[ -n "${configurations}" && ( -n "${AIO}" || -n "${elasticsearch}" || -n "${kibana}" || -n "${wazuh}" || -n "${overwrite}" || -n "${start_elastic_cluster}" || -n "${tar_conf}" || -n "${uninstall}" ) ]]; then
        logger -e "The argument -c|--create-configurations can't be used with -a, -k, -e, -u or -w arguments."
        exit 1
    fi

    # -------------- Overwrite --------------------------------------
    if [ -n "${overwrite}" ] && [ -z "${AIO}" ] && [ -z "${elasticsearch}" ] && [ -z "${kibana}" ] && [ -z "${wazuh}" ]; then
        logger -e "The argument -o|--overwrite must be used with -a, -k, -e or -w. If you want to uninstall all the components use -u|--uninstall."
        exit 1
    fi

    # -------------- Uninstall --------------------------------------

    if [ -n "${uninstall}" ]; then

        if [ -n "$AIO" ] || [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
        logger -e "The argument -u|--uninstall can't be used with -a, -k, -e or -w. If you want to overwrite the components use -o|--overwrite."
        exit 1
        fi

        if ! [ ${uninstall_component_name} == "all" -o ${uninstall_component_name} == "manager" -o ${uninstall_component_name} == "elasticsearch" -o ${uninstall_component_name} == "kibana" ]; then
            logger -e "The argument -u|--uninstall only accepts the following parameters: all, manager, elasticsearch or kibana."
            exit 1
        fi

    fi

    # -------------- All-In-One -------------------------------------

    if [ -n "${AIO}" ]; then

        if [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "Argument -a|--all-in-one is not compatible with -e|--elasticsearch, -k|--kibana or -w|--wazuh-server"
            exit 1
        fi

        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${elasticsearchinstalled}" ] || [ -n "${elastic_remaining_files}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ] || [ -n "${kibanainstalled}" ] || [ -n "${kibana_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                uninstall_module_name="wazuh"
                rollBack
            else
                logger -e "Some the Wazuh components were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
                exit 1
            fi
        fi
    fi

    # -------------- Elasticsearch ----------------------------------

    if [ -n "${elasticsearch}" ]; then

        if [ -n "${elasticsearchinstalled}" ] || [ -n "${elastic_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                uninstall_module_name="elasticsearch"
                rollBack
            else
                logger -e "Elasticsearch is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Kibana -----------------------------------------

    if [ -n "${kibana}" ]; then
        if [ -n "${kibanainstalled}" ] || [ -n "${kibana_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                uninstall_module_name="kibana"
                rollBack
            else
                logger -e "Kibana is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Wazuh ------------------------------------------

    if [ -n "${wazuh}" ]; then
        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack
            else
                logger -e "Wazuh is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi

        if [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack
            else
                logger -e "Filebeat is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Cluster start ----------------------------------

    if [[ -n "${start_elastic_cluster}" && ( -z "${elasticsearchinstalled}" || -z "${elastic_remaining_files}") ]]; then
        logger -e "The argument -s|--start-cluster need elasticsearch installed. Run the script with the parameter first --elasticsearch <elasticsearch-node-name>."
        exit 1
    fi
    if [[ -n "${start_elastic_cluster}" && ( -n "${AIO}" || -n "${elasticsearch}" || -n "${kibana}" || -n "${wazuh}" || -n "${overwrite}" || -n "${configurations}" || -n "${tar_conf}" || -n "${uninstall}") ]]; then
        logger -e "The argument -s|--start-cluster can't be used with -a, -k, -e or -w arguments."
        exit 1
    fi

    # -------------- Global -----------------------------------------

    if [[ -z "${AIO}" && -z "${elasticsearch}" && -z "${kibana}" && -z "${wazuh}" && -z "${start_elastic_cluster}" && -z "${configurations}" && -z "${uninstall}" ]]; then
        logger -e "At least one of these arguments is necessary -a|--all-in-one, -c|--create-configurations, -e|--elasticsearch <elasticsearch-node-name>, -k|--kibana <kibana-node-name>, -s|--start-cluster, -w|--wazuh-server <wazuh-node-name>, -u|--uninstall"
        exit 1
    fi

}

function checkHealth() {

    checkSpecs
    if [ -z "${cores}" ]; then
        logger -e "The script needs to parse the file '${coresFile}' to check the minimum required hardware of CPU cores."
        logger "Use the --ignore-health-check parameter to dismiss the recommended minimum hardware requirements check."
        exit 1
    fi
    if [ -z "${ram_gb}" ]; then
        logger -e "The command 'free' is required to check the minimum required hardware of RAM."
        logger "Use the --ignore-health-check parameter to dismiss the recommended minimum hardware requirements check."
        exit 1
    fi

    if [ -n "${cores}" ] && [ -n "${ram_gb}" ]; then

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
            echo "${cores}"
            if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1
            else
                logger "Check recommended minimum hardware requirements for AIO done."
            fi
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

    if [ "${sys_type}" == "yum" ]; then
        elasticsearchinstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch | grep -v kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        elasticsearchinstalled=$(zypper packages | grep opendistroforelasticsearch | grep -v kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        elasticsearchinstalled=$(apt list --installed 2>/dev/null | grep opendistroforelasticsearch | grep -v kibana)
    fi

    if [ "${sys_type}" == "yum" ]; then
        filebeatinstalled=$(yum list installed 2>/dev/null | grep filebeat)
    elif [ "${sys_type}" == "zypper" ]; then
        filebeatinstalled=$(zypper packages | grep filebeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeatinstalled=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ "${sys_type}" == "yum" ]; then
        kibanainstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch-kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        kibanainstalled=$(zypper packages | grep opendistroforelasticsearch-kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        kibanainstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch-kibana)
    fi

    checkWazuhRemainingFiles
    checkFilebeatRemainingFiles
    checkElasticRemainingFiles
    checkKibanaRemainingFiles

}

function checkWazuhRemainingFiles() {
    if [ -d "/var/ossec" ]; then
        wazuh_remaining_files=1
    else
        wazuh_remaining_files=""
    fi
}

function checkFilebeatRemainingFiles() {
    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        filebeat_remaining_files=1
    else
        filebeat_remaining_files=""
    fi
}

function checkElasticRemainingFiles() {
    if [ -d "/var/lib/elasticsearch/" ] || [ -d "/usr/share/elasticsearch" ] || [ -d "/etc/elasticsearch" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        elastic_remaining_files=1
    else
        elastic_remaining_files=""
    fi
}

function checkKibanaRemainingFiles() {
    if [ -d "/var/lib/kibana/" ] || [ -d "/usr/share/kibana" ] || [ -d "/etc/kibana" ]; then
        kibana_remaining_files=1
    else
        kibana_remaining_files=""
    fi
}

# This function ensures different names in the config.yml file.
function checkNames() {

    if [ -n "${einame}" ] && [ -n "${kiname}" ] && [ "${einame}" == "${kiname}" ]; then
        logger -e "The node names for Elastisearch and Kibana must be different."
        exit 1
    fi

    if [ -n "${einame}" ] && [ -n "${winame}" ] && [ "${einame}" == "${winame}" ]; then
        logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${kiname}" ] && [ "${winame}" == "${kiname}" ]; then
        logger -e "The node names for Wazuh and Kibana must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -z "$(echo "${wazuh_servers_node_names[@]}" | grep -w "${winame}")" ]; then
        logger -e "The Wazuh server node name ${winame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${einame}" ] && [ -z "$(echo "${elasticsearch_node_names[@]}" | grep -w "${einame}")" ]; then
        logger -e "The Elasticsearch node name ${einame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${kiname}" ] && [ -z "$(echo "${kibana_node_names[@]}" | grep -w "${kiname}")" ]; then
        logger -e "The Kibana node name ${kiname} does not appear on the configuration file."
        exit 1
    fi

}

# This function checks if the target certificates are created before to start the installation.
function checkPreviousCertificates() {

    if [ ! -f "${tar_file}" ]; then
        logger -e "No certificates file found (${tar_file}). Run the script with the option -c|--certificates to create automatically or copy them from the node where they were created."
        exit 1
    fi

    if [ -n "${einame}" ]; then
        if ! $(tar -tf "${tar_file}" | grep -q "${einame}".pem) || ! $(tar -tf "${tar_file}" | grep -q "${einame}"-key.pem); then
            logger -e "There is no certificate for the elasticsearch node ${einame} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${kiname}" ]; then
        if ! $(tar -tf "${tar_file}" | grep -q "${kiname}".pem) || ! $(tar -tf "${tar_file}" | grep -q "${kiname}"-key.pem); then
            logger -e "There is no certificate for the kibana node ${kiname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${winame}" ]; then
        if ! $(tar -tf "${tar_file}" | grep -q "${winame}".pem) || ! $(tar -tf "${tar_file}" | grep -q "${winame}"-key.pem); then
            logger -e "There is no certificate for the wazuh server node ${winame} in ${tar_file}."
            exit 1
        fi
    fi

}

function checkSpecs() {

    coresFile="/proc/cpuinfo"
    if [ -f "$coresFile" ]; then
        cores=$(cat "$coresFile" | grep -c processor )
    else
        logger -e "The $coresFile does not exist."
    fi

    if [ -n "$(command -v free)" ]; then
        ram_gb=$(free -m | awk '/^Mem:/{print $2}')
    else
        memFile="/proc/meminfo"
        if [ -f "$memFile" ]; then
            MEMinKB=$(cat "$memFile" | grep MemTotal | awk '/^MemTotal:/{print $2}')
            ram_gb=$(( $MEMinKB / 1024 ))
        else
            logger -e "The $coresFile does not exist."
        fi
    fi






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
        logger -e "Couldn'd find type of system"
        exit 1
    fi

}

function checkTools() {

    # -------------- Check tools required to run the script (awk, sed, etc.) -----------------------------------------

    toolList=(  "awk" "cat" "chown" "cp" "curl" "echo" "export"
                "free" "grep" "kill" "mkdir" "mv" "rm" "sed"
                "sudo" "tar" "touch" "uname")

    missingtoolsList=()
    for command in "${toolList[@]}"
    do
        if [ -z "$(command -v ${command})" ]; then
            missingtoolsList+="${command}, "
        fi
    done

    if [ -n "${missingtoolsList}" ]; then

        logger "---------------------------------- Missing tools -----------------------------------"
        logger "The following command or commands are not present in the system: ${missingtoolsList} and must it is / they are necessary for the correct use of this tool."
        exit 1

    fi

}