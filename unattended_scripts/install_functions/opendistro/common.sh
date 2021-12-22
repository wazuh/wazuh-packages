# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

if [ -n "${development}" ]; then
    repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"
    repobaseurl="https://packages-dev.wazuh.com/pre-release"
    reporelease="unstable"
else
    repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
    repobaseurl="https://packages.wazuh.com/4.x"
    reporelease="stable"
fi

filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/'${wazuh_major}'/extensions/elasticsearch/7.x/wazuh-template.json"
filebeat_wazuh_module="'${repobaseurl}'/filebeat/wazuh-filebeat-0.1.tar.gz"
kibana_wazuh_module="'${repobaseurl}'/ui/kibana/wazuh_kibana-'${wazuh_version}'_'${elasticsearch_oss_version}'-'${wazuh_kibana_plugin_revision}'.zip"

getConfig() {
    if [ -n "${local}" ]; then
        cp ${base_path}/${config_path}/$1 $2
    else
        curl -so $2 ${resources_config}/$1
    fi
    if [ $? != 0 ]; then
        logger -e "Unable to find config $1. Exiting"
        exit 1
    fi
}

checkSystem() {
    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
    elif [ -n "$(command -v zypper)" ]; then
        sys_type="zypper"   
        sep="-"  
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"   
        sep="="
    fi
    ((progressbar_status++))
}

checknames() {

    if [ -n ${einame} ] && [[ ! "${elasticsearch_node_names[@]}" =~ "${einame}" ]]; then
        logger -e "The name given for the elasticsearch node does not appear on the configuration file"
        exit 1;
    fi

    if [ -n ${winame} ] && [[ ! "${wazuh_servers_node_names[@]}" =~ "${winame}" ]]; then
        logger -e "The name given for the wazuh server node does not appear on the configuration file"
        exit 1;
    fi
}

checkArch() {
    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi
}

installPrerequisites() {
    logger "Installing all necessary utilities for the installation."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install curl unzip wget libcap tar -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"         
        eval "zypper -n install libcap-progs tar ${debug} || zypper -n install libcap2 tar ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
        ((progressbar_status++))
    fi
}

addWazuhrepo() {
    logger "Adding the Wazuh repository."

    if [ -n ${development} ]; then
        if [ ${sys_type} == "yum" ]; then
            eval "rm -f /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ ${sys_type} == "zypper" ]; then
            eval "rm -f /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ ${sys_type} == "apt-get" ]; then
            eval "rm -f /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    fi

    if [ ! -f /etc/yum.repos.d/wazuh.repo ] && [ ! -f /etc/zypp/repos.d/wazuh.repo ] && [ ! -f /etc/apt/sources.list.d/wazuh.list ] ; then
        if [ ${sys_type} == "yum" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ ${sys_type} == "zypper" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ ${sys_type} == "apt-get" ]; then
            eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
            eval "echo \"deb ${repobaseurl}/apt/ ${reporelease} main\" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
            eval "apt-get update -q ${debug}"
        fi
    else
        logger "Wazuh repository already exists skipping"
    fi
    logger "Done"
    ((progressbar_status++))
}

restoreWazuhrepo() {
    if [ -n "${development}" ]; then
        logger "Setting the Wazuh repository to production"
        if [ ${sys_type} == "yum" ] && [ -f /etc/yum.repos.d/wazuh.repo ]; then
            file="/etc/yum.repos.d/wazuh.repo"
        elif [ ${sys_type} == "zypper" ] && [ -f /etc/zypp/repos.d/wazuh.repo ]; then
            file="/etc/zypp/repos.d/wazuh.repo"
        elif [ ${sys_type} == "apt-get" ] && [ -f /etc/apt/sources.list.d/wazuh.list ]; then
            file="/etc/apt/sources.list.d/wazuh.list"
        else
            logger "Wazuh repository does not exists"
        fi
        eval "sed -i 's/-dev//g' ${file} ${debug}"
        eval "sed -i 's/pre-release/4.x/g' ${file} ${debug}"
        eval "sed -i 's/unstable/stable/g' ${file} ${debug}"
        logger "Done"
    fi
    ((progressbar_status++))
}

checkInstalled() {
    
    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages --installed | grep wazuh-manager | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi    

    if [ -n "${wazuhinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $11}')
        else
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $2}')
        fi    
    fi

    if [ "${sys_type}" == "yum" ]; then
        elasticsearchinstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch)
    elif [ "${sys_type}" == "zypper" ]; then
        elasticsearchinstalled=$(zypper packages --installed | grep opendistroforelasticsearch | grep i+ | grep noarch)
    elif [ "${sys_type}" == "apt-get" ]; then
        elasticsearchinstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch)
    fi 

    if [ -n "${elasticsearchinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            odversion=$(echo ${elasticsearchinstalled} | awk '{print $11}')
        else
            odversion=$(echo ${elasticsearchinstalled} | awk '{print $2}')
        fi  
    fi

    if [ "${sys_type}" == "yum" ]; then
        filebeatinstalled=$(yum list installed 2>/dev/null | grep filebeat)
    elif [ "${sys_type}" == "zypper" ]; then
        filebeatinstalled=$(zypper packages --installed | grep filebeat | grep i+ | grep noarch)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeatinstalled=$(apt list --installed  2>/dev/null | grep filebeat)
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
        kibanainstalled=$(zypper packages --installed | grep opendistroforelasticsearch-kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        kibanainstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch-kibana)
    fi 

    if [ -n "${kibanainstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $11}')
        else
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $2}')
        fi  
    fi  

    if [ -z "${wazuhinstalled}" ] || [ -z "${elasticsearchinstalled}" ] || [ -z "${filebeatinstalled}" ] || [ -z "${kibanainstalled}" ] && [ -n "${uninstall}" ]; then 
        logger -e " No Wazuh components were found on the system."
        exit 1;        
    fi

    if [ -n "${wazuhinstalled}" ] || [ -n "${elasticsearchinstalled}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${kibanainstalled}" ]; then 
        if [ -n "${ow}" ]; then
            overwrite
        
        elif [ -n "${uninstall}" ]; then
            logger -w "Removing the installed items"
            rollBack
        else
            logger -e "All the Wazuh componets were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
            exit 1;
        fi
    fi

}

startService() {

    logger "Starting service $1..."

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi             
    else
        logger -e "${1^} could not start. No service manager found on the system."
        exit 1;
    fi

}

createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "getConfig certificate/config_aio.yml ${base_path}/config.yml ${debug}"
    fi

    readConfig
    mkdir ${base_path}/certs 
    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

specsCheck() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')
    
}

healthCheck() {
    specsCheck
    case "$1" in
        "elasticsearch")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                logger "Check recommended minimum hardware requirements for Elasticsearch done."
                logger "Starting the installation."
            fi
            ;;

        "kibana")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                logger "Check recommended minimum hardware requirements for Kibana done."
                logger "Starting the installation."
            fi
            ;;
        "wazuh")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 1700 ]
            then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                logger "Check recommended minimum hardware requirements for Wazuh Manager done."
                logger "Starting the installation."
            fi
            ;;
        "AIO")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                logger "Check recommended minimum hardware requirements for AIO done."
                logger "Starting the installation."
            fi
            ;;
    esac
    ((progressbar_status++))
}

rollBack() {

    if [ -z "${uninstall}" ]; then
        logger -w "Cleaning the installation" 
    fi  

    if [ -f /etc/yum.repos.d/wazuh.repo ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f /etc/zypp/repos.d/wazuh.repo ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f /etc/apt/sources.list.d/wazuh.list ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi

    if [ -n "${wazuhinstalled}" ]; then
        logger -w "Removing the Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-manager -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-manager ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-manager -y ${debug}"
        fi 
        eval "rm -rf /var/ossec/ ${debug}"
    fi     

    if [ -n "${elasticsearchinstalled}" ]; then
        logger -w "Removing Elasticsearch."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch -y ${debug}"
            eval "yum remove elasticsearch* -y ${debug}"
            eval "yum remove opendistro-* -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-* ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge opendistroforelasticsearch elasticsearch* opendistro-* -y ${debug}"
        fi 
        eval "rm -rf /var/lib/elasticsearch/ ${debug}"
        eval "rm -rf /usr/share/elasticsearch/ ${debug}"
        eval "rm -rf /etc/elasticsearch/ ${debug}"
        eval "rm -rf ./search-guard-tlstool-1.8.zip ${debug}"
        eval "rm -rf ./searchguard ${debug}"
    fi

    if [ -n "${filebeatinstalled}" ]; then
        logger -w "Removing Filebeat."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug}"
        fi 
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [ -n "${kibanainstalled}" ]; then
        logger -w "Removing Kibana."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch-kibana -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge opendistroforelasticsearch-kibana -y ${debug}"
        fi 
        eval "rm -rf /var/lib/kibana/ ${debug}"
        eval "rm -rf /usr/share/kibana/ ${debug}"
        eval "rm -rf /etc/kibana/ ${debug}"
    fi

    if [ -z "${uninstall}" ]; then    
        logger -w "Installation cleaned. Check the /var/log/wazuh-unattended-installation.log file to learn more about the issue."
    fi
}

parse_yaml() {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

readConfig() {
    if [ -f ${base_path}/config.yml ]; then
        eval "$(parse_yaml ${base_path}/config.yml)"
        eval "elasticsearch_node_names=( $(parse_yaml ${base_path}/config.yml | grep nodes_elasticsearch_name | sed 's/nodes_elasticsearch_name=//') )"
        eval "wazuh_servers_node_names=( $(parse_yaml ${base_path}/config.yml | grep nodes_wazuh_servers_name | sed 's/nodes_wazuh_servers_name=//') )"
        eval "kibana_node_names=( $(parse_yaml ${base_path}/config.yml | grep nodes_kibana_name | sed 's/nodes_kibana_name=//') )"

        eval "elasticsearch_node_ips=( $(parse_yaml ${base_path}/config.yml | grep nodes_elasticsearch_ip | sed 's/nodes_elasticsearch_ip=//') )"
        eval "wazuh_servers_node_ips=( $(parse_yaml ${base_path}/config.yml | grep nodes_wazuh_servers_ip | sed 's/nodes_wazuh_servers_ip=//') )"
        eval "kibana_node_ips=( $(parse_yaml ${base_path}/config.yml | grep nodes_kibana_ip | sed 's/nodes_kibana_ip=//') )"

        eval "wazuh_servers_node_types=( $(parse_yaml ${base_path}/config.yml | grep nodes_wazuh_servers_node_type | sed 's/nodes_wazuh_servers_node_type=//') )"

        if [ $(printf '%s\n' "${elasticsearch_node_names[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#elasticsearch_node_names[@]} ]; then 
            logger -e "Duplicated Elasticsearch node names"
            exit 1;
        fi

        if [ $(printf '%s\n' "${elasticsearch_node_ips[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#elasticsearch_node_ips[@]} ]; then 
            logger -e "Duplicated Elasticsearch node ips"
            exit 1;
        fi

        if [ $(printf '%s\n' "${wazuh_servers_node_names[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#wazuh_servers_node_names[@]} ]; then 
            logger -e "Duplicated Wazuh server node names"
            exit 1;
        fi

        if [ $(printf '%s\n' "${wazuh_servers_node_ips[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#wazuh_servers_node_ips[@]} ]; then 
            logger -e "Duplicated Wazuh server node ips"
            exit 1;
        fi

        if [ $(printf '%s\n' "${kibana_node_names[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#kibana_node_names[@]} ]; then 
            logger -e "Duplicated Kibana node names"
            exit 1;
        fi

        if [ $(printf '%s\n' "${kibana_node_ips[@]}"|awk '!($0 in seen){seen[$0];c++} END {print c}') -ne ${#kibana_node_ips[@]} ]; then 
            logger -e "Duplicated Kibana node ips"
            exit 1;
        fi

        if [ ${#wazuh_servers_node_names[@]} -ne ${#wazuh_servers_node_ips[@]} ]; then 
            logger -e "Different number of Wazuh server node names and IPs "
            exit 1;
        fi

        if [ ${#wazuh_servers_node_names[@]} -le 1 ]; then
            if [ ${#wazuh_servers_node_types[@]} -ne 0 ]; then
                logger -e "node_type must be used with more than one Wazuh server"
                exit 1;
            fi
        elif [ ${#wazuh_servers_node_names[@]} -ne ${#wazuh_servers_node_types[@]} ]; then
            logger -e "Different number of Wazuh server node names and node types "
            exit 1;
        elif [ $(grep -o master <<< ${wazuh_servers_node_types[*]} | wc -l) -ne 1 ]; then
            logger -e "Wazuh cluster needs a single master node"
            exit 1;
        elif [ $(grep -o worker <<< ${wazuh_servers_node_types[*]} | wc -l) -ne $(expr ${#wazuh_servers_node_types[@]} - 1)  ]; then
            logger -e "Incorrect number of workers"
            exit 1;
        fi

        if [ ${#kibana_node_names[@]} -ne ${#kibana_node_ips[@]} ]; then 
            logger -e "Different number of Kibana node names and IPs "
            exit 1;
        fi

    else
        logger -e "No configuration file found. ${base_path}/config.yml"
        exit 1;
    fi
}

createClusterKey() {
    openssl rand -hex 16 >> ${base_path}/certs/clusterkey
}

