# Wazuh installer - checks.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function checks_arch() {

    arch=$(uname -m)

    if [ "${arch}" != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

function checks_arguments() {

    # -------------- Configurations ---------------------------------

    if [[ ( -n "${AIO}"  || -n "${configurations}" ) && -f "${tar_file}" ]]; then
            logger -e "File ${tar_file} exists. Please remove it if you want to use a new configuration."
            exit 1
    fi

    if [[ -n "${configurations}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${start_elastic_cluster}" || -n "${tar_conf}" || -n "${uninstall}" ) ]]; then
        logger -e "The argument -c|--create-configurations can't be used with -a, -k, -e, -u or -w arguments."
        exit 1
    fi

    # -------------- Overwrite --------------------------------------


    if [ -n "${overwrite}" ] && [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ]; then
        logger -e "The argument -o|--overwrite must be used with -a, -k, -e or -w. If you want to uninstall all the components use -u|--uninstall"
        exit 1
    fi

    # -------------- Uninstall --------------------------------------

    if [ -n "${uninstall}" ]; then

        if [ -z "${wazuhinstalled}" ] && [ -z "${wazuh_remaining_files}" ]; then
            logger "Wazuh manager components were not found on the system so it was not uninstalled."
        fi

        if [ -z "${filebeatinstalled}" ] && [ -z "${filebeat_remaining_files}" ]; then
            logger "Filebeat components were not found on the system so it was not uninstalled."
        fi

        if [ -z "${indexerinstalled}" ] && [ -z "${indexer_remaining_files}" ]; then
            logger "Elasticsearch components were not found on the system so it was not uninstalled."
        fi

        if [ -z "${dashboardinstalled}" ] && [ -z "${dashboard_remaining_files}" ]; then
            logger "Kibana components were found on the system so it was not uninstalled."
        fi

        if [ -n "$AIO" ] || [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "The argument -u|--uninstall can't be used with -a, -k, -e or -w. If you want to overwrite the components use -o|--overwrite"
            exit 1
        fi
    fi

    # -------------- All-In-One -------------------------------------

    if [ -n "${AIO}" ]; then

        if [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "Argument -a|--all-in-one is not compatible with -e|--elasticsearch, -k|--kibana or -w|--wazuh-server"
            exit 1
        fi

        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${indexerinstalled}" ] || [ -n "${indexer_remaining_files}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ] || [ -n "${dashboardinstalled}" ] || [ -n "${dashboard_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                common_rollBack
            else
                logger -e "Some the Wazuh components were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
                exit 1
            fi
        fi
    fi

    # -------------- Elasticsearch ----------------------------------

    if [ -n "${indexer}" ]; then

        if [ -n "${indexerinstalled}" ] || [ -n "${indexer_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                common_rollBack
            else
                logger -e "Elasticsearch is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Kibana -----------------------------------------

    if [ -n "${dashboard}" ]; then
        if [ -n "${dashboardinstalled}" ] || [ -n "${dashboard_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                common_rollBack
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
                common_rollBack
            else
                logger -e "Wazuh is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi

        if [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ]; then
            if [ -n "${overwrite}" ]; then
                common_rollBack
            else
                logger -e "Filebeat is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi

    # -------------- Cluster start ----------------------------------

    if [[ -n "${start_elastic_cluster}" && ( -n "${AIO}" || -n "${indexer}" || -n "${dashboard}" || -n "${wazuh}" || -n "${overwrite}" || -n "${configurations}" || -n "${tar_conf}" || -n "${uninstall}") ]]; then
        logger -e "The argument -s|--start-cluster can't be used with -a, -k, -e or -w arguments."
        exit 1
    fi

    # -------------- Global -----------------------------------------

    if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_elastic_cluster}" ] && [ -z "${configurations}" ] && [ -z "${uninstall}"]; then
        logger -e "At least one of these arguments is necessary -a|--all-in-one, -c|--create-configurations, -e|--elasticsearch <elasticsearch-node-name>, -k|--kibana <kibana-node-name>, -s|--start-cluster, -w|--wazuh-server <wazuh-node-name>, -u|--uninstall"
        exit 1
    fi

}

function checkFirewalls() {


    firewallsList=( "iptables"
                    "nft"
                    "ufw"
                    "firewall-cmd")

    portsTCPLists=( "1514"
                    "1515"
                    "1516"
                    "55000"
                    "9200"
                    "9300"
                    "9400"
                    "443")

    iptablesBlockedPortList=()
    nftBlockedPortList=()
    ufwBlockedPortList=()
    firewall_cmdBlockedPortList=()

    for command in "${firewallsList[@]}"; do

        if [ -n "$(command -v ${command})" ]; then
            logger -d "The $command command is present on this system. This could affect the correct communication between Wazuh components. We will proceed to try to validate firewall rules that may affect the processes and report what is found."

            case ${command} in
                iptables )
                    for port in "${portsTCPLists[@]}"; do
                        if [ -n "$(${command} -L -n | grep DROP | grep "^$port$" )" ]; then
                            iptablesBlockedPortList+="${port}, "
                        fi
                    done
                    ;;
                nft )
                    for port in "${portsTCPLists[@]}"; do
                        if [ -n "$(${command} list ruleset | grep drop | grep "^$port$" )" ]; then
                            nftBlockedPortList+="${port}, "
                        fi
                    done
                    ;;
                ufw )
                    for port in "${portsTCPLists[@]}"; do
                        if [ -n "$(cat /etc/ufw/user.rules | grep DROP | grep "^$port$" )" ]; then
                            ufwBlockedPortList+="${port}, "
                        fi
                    done
                    ;;
                firewall-cmd )
                    for port in "${portsTCPLists[@]}"; do
                        if [ -n "$(${command}  --list-all | grep "^$port$" )" ]; then
                            firewall_cmdBlockedPortList+="${port}, "
                        fi
                    done
                    ;;
            esac

        fi
    done

    if [ -n "${iptablesBlockedPortList}" ]; then
        logger "iptables blocked port report: ${iptablesBlockedPortList} this ports must be opened."
    fi
    if [ -n "${nftBlockedPortList}" ]; then
        logger "nft blocked port report: ${nftBlockedPortList} this ports must be opened."
    fi
    if [ -n "${ufwBlockedPortList}" ]; then
        logger "ufw blocked port report: ${ufwBlockedPortList} this ports must be opened."
    fi
    if [ -n "${firewall_cmdBlockedPortList}" ]; then
        logger "firewall-cmd blocked port report: ${firewall_cmdBlockedPortList} this ports must be opened."
    fi

    if [ -n "${iptablesBlockedPortList}" ] || [ -n "${firewallstatus}" ] || [ -n "${firewallstatus}" ] || [ -n "${firewallstatus}" ]; then
        logger -e "Please check your firewall. To then repeat the installation of Wazuh."
        exit 1
    fi
}

function checks_health() {

    checks_specifications
    if [ -n "${indexer}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for Elasticsearch done."
        fi
    fi

    if [ -n "${dashboard}" ]; then
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

    if [ -n "${AIO}" ]; then
        if [ "${cores}" -lt 2 ] || [ "${ram_gb}" -lt 3700 ]; then
            logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
            exit 1
        else
            logger "Check recommended minimum hardware requirements for AIO done."
        fi
    fi

}

function checks_installed() {

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

    if [ "${sys_type}" == "yum" ]; then
        indexerinstalled=$(yum list installed 2>/dev/null | grep wazuh-indexer | grep -v kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        indexerinstalled=$(zypper packages | grep wazuh-indexer | grep -v kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        indexerinstalled=$(apt list --installed 2>/dev/null | grep wazuh-indexer | grep -v kibana)
    fi

    if [ -d "/var/lib/wazuh-indexer/" ] || [ -d "/usr/share/wazuh-indexer" ] || [ -d "/etc/wazuh-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        indexer_remaining_files=1
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

    if [ "${sys_type}" == "yum" ]; then
        dashboardinstalled=$(yum list installed 2>/dev/null | grep wazuh-dashboard)
    elif [ "${sys_type}" == "zypper" ]; then
        dashboardinstalled=$(zypper packages | grep wazuh-dashboard | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboardinstalled=$(apt list --installed  2>/dev/null | grep wazuh-dashboard)
    fi

    if [ -d "/var/lib/wazuh-dashboard/" ] || [ -d "/usr/share/wazuh-dashboard" ] || [ -d "/etc/wazuh-dashboard" ] || [ -d "/run/wazuh-dashboard/" ]; then
        dashboard_remaining_files=1
    fi

}

# This function ensures different names in the config.yml file.
function checks_names() {

    if [ -n "${indxname}" ] && [ -n "${dashname}" ] && [ "${indxname}" == "${dashname}" ]; then
        logger -e "The node names for Elastisearch and Kibana must be different."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -n "${winame}" ] && [ "${indxname}" == "${winame}" ]; then
        logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -n "${dashname}" ] && [ "${winame}" == "${dashname}" ]; then
        logger -e "The node names for Wazuh and Kibana must be different."
        exit 1
    fi

    if [ -n "${winame}" ] && [ -z "$(echo "${server_node_names[@]}" | grep -w "${winame}")" ]; then
        logger -e "The Wazuh server node name ${winame} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${indxname}" ] && [ -z "$(echo "${indexer_node_names[@]}" | grep -w "${indxname}")" ]; then
        logger -e "The Elasticsearch node name ${indxname} does not appear on the configuration file."
        exit 1
    fi

    if [ -n "${dashname}" ] && [ -z "$(echo "${dashboard_node_names[@]}" | grep -w "${dashname}")" ]; then
        logger -e "The Kibana node name ${dashname} does not appear on the configuration file."
        exit 1
    fi

}

# This function checks if the target certificates are created before to start the installation.
function checks_previousCertificate() {

    if [ ! -f "${tar_file}" ]; then
        logger -e "No certificates file found (${tar_file}). Run the script with the option -c|--certificates to create automatically or copy them from the node where they were created."
        exit 1
    fi

    if [ -n "${indxname}" ]; then
        if ! $(tar -tf "${tar_file}" | grep -q "${indxname}".pem) || ! $(tar -tf "${tar_file}" | grep -q "${indxname}"-key.pem); then
            logger -e "There is no certificate for the elasticsearch node ${indxname} in ${tar_file}."
            exit 1
        fi
    fi

    if [ -n "${dashname}" ]; then
        if ! $(tar -tf "${tar_file}" | grep -q "${dashname}".pem) || ! $(tar -tf "${tar_file}" | grep -q "${dashname}"-key.pem); then
            logger -e "There is no certificate for the kibana node ${dashname} in ${tar_file}."
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

function checks_specifications() {

    cores=$(cat /proc/cpuinfo | grep -c processor )
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

}

function checks_system() {

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
