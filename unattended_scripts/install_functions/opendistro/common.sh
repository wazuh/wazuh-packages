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
kibana_wazuh_plugin="'${repobaseurl}'/ui/kibana/wazuh_kibana-'${wazuh_version}'_'${elasticsearch_oss_version}'-'${wazuh_kibana_plugin_revision}'.zip"

function getConfig() {
    if [ "$#" -ne 2 ]; then
        logger -e "getConfig must be called with 2 arguments."
        exit 1
    fi
    if [ -n "${local}" ]; then
        cp ${base_path}/${config_path}/$1 $2
    else
        curl -so $2 ${resources_config}/$1
    fi
    if [ $? != 0 ]; then
        logger -e "Unable to find config $1. Exiting."
        exit 1
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
        logger -e "Couldn't find type of system based on the installer software"
        exit 1
    fi
}

function checkNames() {

    if [[ -n ${einame} ]] && [[ -n ${kiname} ]] && ([[ "${einame}" == "${kiname}" ]]); then
        logger -e "The node names for Elastisearch and Kibana must be different."
        exit 1
    fi

    if [[ -n ${einame} ]] && [[ -n ${winame} ]] && ([[ "${einame}" == "${winame}" ]]); then
        logger -e "The node names for Elastisearch and Wazuh must be different."
        exit 1
    fi

    if [[ -n ${winame} ]] && [[ -n ${kiname} ]] && ([[ "${winame}" == "${kiname}" ]]); then
        logger -e "The node names for Wazuh and Kibana must be different."
        exit 1
    fi

    if [[ -n ${einame} ]]; then
        if [[ -z "$(echo ${elasticsearch_node_names[@]} | grep -w $einame)" ]]; then
            logger -e "The name given for the Elasticsearch node does not appear on the configuration file."
            exit 1
        fi
    fi

    if [[ -n ${winame} ]]; then
        if [[ -z "$(echo ${wazuh_servers_node_names[@]} | grep -w $winame)" ]]; then
            logger -e "The name given for the Wazuh server node does not appear on the configuration file."
            exit 1
        fi
    fi

    if [[ -n ${kiname} ]]; then
        if [[ -z "$(echo ${kibana_node_names[@]} | grep -w $kiname)" ]]; then
            logger -e "The name given for the Kibana node does not appear on the configuration file."
            exit 1
        fi
    fi

}

function checkArch() {
    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1
    fi
}

function installPrerequisites() {

    logger "Starting all necessary utility installation."

    openssl=""
    if [ -z "$(command -v openssl)" ]; then
        openssl="openssl"
    fi

    if [ ${sys_type} == "yum" ]; then
        eval "yum install curl unzip wget libcap tar gnupg ${openssl} -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"         
        eval "zypper -n install libcap-progs tar gnupg ${openssl} ${debug} || zypper -n install libcap2 tar gnupg ${openssl} ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg ${openssl} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1
    else
        logger "All necessary utility installation finished."
    fi
}

function addWazuhrepo() {

    logger "Adding the Wazuh repository."

    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            eval "rm -f /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "rm -f /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "rm -f /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    fi

    if [ ! -f /etc/yum.repos.d/wazuh.repo ] && [ ! -f /etc/zypp/repos.d/wazuh.repo ] && [ ! -f /etc/apt/sources.list.d/wazuh.list ] ; then
        if [ "${sys_type}" == "yum" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
            eval "echo \"deb ${repobaseurl}/apt/ ${reporelease} main\" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
            eval "apt-get update -q ${debug}"
        fi
    else
        logger "Wazuh repository already exists skipping."
    fi
    logger "Wazuh repository added."
}

function restoreWazuhrepo() {
    if [ -n "${development}" ]; then
        logger "Setting the Wazuh repository to production."
        if [ "${sys_type}" == "yum" ] && [ -f /etc/yum.repos.d/wazuh.repo ]; then
            file="/etc/yum.repos.d/wazuh.repo"
        elif [ "${sys_type}" == "zypper" ] && [ -f /etc/zypp/repos.d/wazuh.repo ]; then
            file="/etc/zypp/repos.d/wazuh.repo"
        elif [ "${sys_type}" == "apt-get" ] && [ -f /etc/apt/sources.list.d/wazuh.list ]; then
            file="/etc/apt/sources.list.d/wazuh.list"
        else
            logger -w "Wazuh repository does not exists."
        fi
        eval "sed -i 's/-dev//g' ${file} ${debug}"
        eval "sed -i 's/pre-release/4.x/g' ${file} ${debug}"
        eval "sed -i 's/unstable/stable/g' ${file} ${debug}"
        logger "The Wazuh repository set to production."
    fi
}

function checkInstalled() {
    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages | grep wazuh-manager | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi

    if [ -d /var/ossec ]; then
        wazuh_remaining_files=1
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
        elasticsearchinstalled=$(zypper packages | grep opendistroforelasticsearch | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        elasticsearchinstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch)
    fi

    if [ -d /var/lib/elasticsearch/ ] || [ -d /usr/share/elasticsearch ] || [ -d /etc/elasticsearch ] || [ -f ${base_path}/search-guard-tlstool* ]; then
        elastic_remaining_files=1
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
        filebeatinstalled=$(zypper packages | grep filebeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeatinstalled=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ -d /var/lib/filebeat/ ] || [ -d /usr/share/filebeat ] || [ -d /etc/filebeat ]; then
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

    if [ -d /var/lib/kibana/ ] || [ -d /usr/share/kibana ] || [ -d /etc/kibana ]; then
        kibana_remaining_files=1
    fi

    if [ -n "${kibanainstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $11}')
        else
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $2}')
        fi
    fi
}

function startService() {

    logger "Starting service $1."

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1
        else
            logger "${1^} service started."
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    else
        logger -e "${1^} could not start. No service manager found on the system."
        exit 1
    fi

}

function createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "getConfig certificate/config_aio.yml ${base_path}/config.yml ${debug}"
    fi

    mkdir ${base_path}/certs

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

function checkPreviousCertificates() {

    if [ ! -z ${einame} ]; then
        if [ -f ${base_path}/certs/${einame}.pem ] || [ f ${base_path}/certs/${einame}-key.pem ]; then
            logger "Certificates were found for the Elasticsearch node: ${einame} in ${base_path}/certs."
        else
            logger -e "Missing certificate for the Elasticsearch node: ${einame} in ${base_path}/certs."
            exit 1
        fi

    fi

    if [ ! -z ${winame} ]; then
        if [ -f ${base_path}/certs/${winame}.pem ] || [ -f ${base_path}/certs/${winame}-key.pem ]; then
            logger "Certificates were found for the Wazuh server node: ${einame} in ${base_path}/certs."
        else
            logger -e "Missing certificate for the Wazuh server node: ${einame} in ${base_path}/certs."
            exit 1
        fi
    fi

    if [ ! -z ${kiname} ]; then
        if [ -f ${base_path}/certs/${kiname}.pem ] || [ -f ${base_path}/certs/${kiname}-key.pem ]; then
            logger "Certificates were found for the Kibana node: ${einame} in ${base_path}/certs."
        else
            logger -e "Missing certificate for the Kibana node: ${einame} in ${base_path}/certs."
            exit 1
        fi
    fi

}

function specsCheck() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')
    
}

function healthCheck() {
    specsCheck
    case "$1" in
        "elasticsearch")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1
            else
                logger "Check recommended minimum hardware requirements for Elasticsearch done."
                logger "Starting the installation."
            fi
            ;;

        "kibana")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1
            else
                logger "Check recommended minimum hardware requirements for Kibana done."
                logger "Starting the installation."
            fi
            ;;
        "wazuh")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 1700 ]
            then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1
            else
                logger "Check recommended minimum hardware requirements for Wazuh Manager done."
                logger "Starting the installation."
            fi
            ;;
        "AIO")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1
            else
                logger "Check recommended minimum hardware requirements for AIO done."
                logger "Starting the installation."
            fi
            ;;
    esac
}

function rollBack() {

    if [ -z "${uninstall}" ] && [ -z "$1" ]; then
        logger "Cleaning the installation."
    fi  

    if [ -f /etc/yum.repos.d/wazuh.repo ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f /etc/zypp/repos.d/wazuh.repo ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f /etc/apt/sources.list.d/wazuh.list ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi

    if [ -n "${wazuhinstalled}" ] && ([ -z "$1" ] || [ "$1" == "wazuh" ]); then
        logger -w "Removing the Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-manager -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-manager ${debug}"
            eval "rm -f /etc/init.d/wazuh-manager ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-manager -y ${debug}"
        fi 
        
    fi

    if ([ -n "${wazuh_remaining_files}" ] || [ -n "$wazuhinstalled" ]) && ([ -z "$1" ] || [ "$1" == "wazuh" ]); then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [ -n "${elasticsearchinstalled}" ] && ([ -z "$1" ] || [ "$1" == "elasticsearch" ]); then
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
    fi

    if ([ -n "${elastic_remaining_files}" ] || [ -n "$elasticsearchinstalled" ]) && ([ -z "$1" ] || [ "$1" == "elasticsearch" ]); then
        eval "rm -rf /var/lib/elasticsearch/ ${debug}"
        eval "rm -rf /usr/share/elasticsearch/ ${debug}"
        eval "rm -rf /etc/elasticsearch/ ${debug}"
    fi

    if [ -n "${filebeatinstalled}" ] && ([ -z "$1" ] || [ "$1" == "filebeat" ]); then
        logger -w "Removing Filebeat."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug}"
        fi
    fi

    if ([ -n "${filebeat_remaining_files}" ] || [ -n "$filebeatinstalled" ]) && ([ -z "$1" ] || [ "$1" == "filebeat" ]); then
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [ -n "${kibanainstalled}" ] && ([ -z "$1" ] || [ "$1" == "kibana" ]); then
        logger -w "Removing Kibana."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch-kibana -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge opendistroforelasticsearch-kibana -y ${debug}"
        fi
    fi

    if ([ -n "${kibana_remaining_files}" ] || [ -n "$kibanainstalled" ]) && ([ -z "$1" ] || [ "$1" == "kibana" ]); then
        eval "rm -rf /var/lib/kibana/ ${debug}"
        eval "rm -rf /usr/share/kibana/ ${debug}"
        eval "rm -rf /etc/kibana/ ${debug}"
    fi

    if [ -d "/var/log/elasticsearch" ]; then
        eval "rm -rf /var/log/elasticsearch/ ${debug}"
    fi

    if [ -d "/var/log/filebeat" ]; then
        eval "rm -rf /var/log/filebeat/ ${debug}"
    fi

    if [ -f "/securityadmin_demo.sh" ]; then
        eval "rm -f /securityadmin_demo.sh ${debug}"
    fi

    if [ -f "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service" ]; then
        eval "rm -f /etc/systemd/system/multi-user.target.wants/wazuh-manager.service ${debug}"
    fi

    if [ -f "/etc/systemd/system/multi-user.target.wants/filebeat.service" ]; then
        eval "rm -f /etc/systemd/system/multi-user.target.wants/filebeat.service ${debug}"
    fi

    if [ -f "/etc/systemd/system/multi-user.target.wants/elasticsearch.service" ]; then
        eval "rm -f /etc/systemd/system/multi-user.target.wants/elasticsearch.service ${debug}"
    fi

    if [ -f "/etc/systemd/system/multi-user.target.wants/kibana.service" ]; then
        eval "rm -f /etc/systemd/system/multi-user.target.wants/kibana.service ${debug}"
    fi

    if [ -f "/etc/systemd/system/kibana.service" ]; then
        eval "rm -f /etc/systemd/system/kibana.service ${debug}"
    fi

    if [ -f "/lib/firewalld/services/kibana.xml" ]; then
        eval "rm -f /lib/firewalld/services/kibana.xml ${debug}"
    fi

    if [ -f "/lib/firewalld/services/elasticsearch.xml" ]; then
        eval "rm -f /lib/firewalld/services/elasticsearch.xml ${debug}"
    fi

    if [ -d "/etc/systemd/system/elasticsearch.service.wants" ]; then
        eval "rm -rf /etc/systemd/system/elasticsearch.service.wants ${debug}"
    fi

    if [ -z "${uninstall}" ] && [ -z "$1" ]; then
        logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
    fi
}

function createClusterKey() {
    openssl rand -hex 16 >> ${base_path}/certs/clusterkey
}

function checkArguments() {

    if ([ -n "$AIO" ] || [ -n "$certificates" ]) && [ -d ${base_path}/certs ]; then
            logger -e "Folder ${base_path}/certs exists. Please remove the certificates folder if you want to create new certificates."
            exit 1
    fi

    if [ -n "$overwrite" ] && [ -z "$AIO" ] && [ -z "$elasticsearch" ] && [ -z "$kibana" ] && [ -z "$wazuh" ]; then 
        logger -e "The argument -o|--overwrite can't be used by itself. If you want to uninstall the components use -u|--uninstall"
        exit 1
    fi

    if [ -n "${uninstall}" ]; then

        if [ -z "${wazuhinstalled}" ] || [ -z "$wazuh_remaining_files" ]; then
            logger -w "Can't uninstall Wazuh manager. No components were found on the system."
        fi

        if [ -z "${filebeatinstalled}" ] || [ -z "$filebeat_remaining_files" ]; then
            logger -w "Can't uninstall Filebeat. No components were found on the system."
        fi

        if [ -z "${elasticsearchinstalled}" ] || [ -z "$elastic_remaining_files" ]; then
            logger -w "Can't uninstall Elasticsearch. No components were found on the system."
        fi

        if [ -z "${kibanainstalled}" ] || [ -z "$kibana_remaining_files" ]; then
            logger -w "Can't uninstall. No components were found on the system."
        fi

        if [ -n "$AIO" ] || [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "The argument -u|--uninstall can't be used with -a, -k, -e or -w. If you want to overwrite the components use -o|--overwrite"
            exit 1
        fi
    fi

    if [ -n "$AIO" ]; then

        if [ -n "$elasticsearch" ] || [ -n "$kibana" ] || [ -n "$wazuh" ]; then
            logger -e "Argument -a|--all-in-one is not compatible with -e|--elasticsearch, -k|--kibana or -w|--wazuh-server"
            exit 1
        fi

        if [ -n "${wazuhinstalled}" ] || [ -n "$wazuh_remaining_files" ] || [ -n "${elasticsearchinstalled}" ] || [ -n "$elastic_remaining_files" ] || [ -n "${filebeatinstalled}" ] || [ -n "$filebeat_remaining_files" ] || [ -n "${kibanainstalled}" ] || [ -n "$kibana_remaining_files" ]; then
            if [ -n "${overwrite}" ]; then
                rollBack
            else
                logger -e "Some the Wazuh components were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
                exit 1
            fi
        fi
    fi

    if [ -n "$elasticsearch" ]; then

        if [ -n "$elasticsearchinstalled" ] || [ -n "$elastic_remaining_files" ]; then
            if [ -n "$overwrite" ]; then
                rollBack "elasticsearch"
            else 
                logger -e "Elasticsearch is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit
            fi
        fi
    fi

    if [ -n "$kibana" ]; then

        if [ -n "$kibanainstalled" ] || [ -n "$kibana_remaining_files" ]; then
            if [ -n "$overwrite" ]; then
                rollBack "kibana"
            else 
                logger -e "Kibana is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 
            fi
        fi
    fi

    if [ -n "$wazuh" ]; then
        if [ -n "$wazuhinstalled" ] || [ -n "$wazuh_remaining_files" ]; then
            if [ -n "$overwrite" ]; then
                rollBack "wazuh"
            else 
                logger -e "Wazuh is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 
            fi
        fi

        if [ -n "$filebeatinstalled" ] || [ -n "$filebeat_remaining_files" ]; then
            if [ -n "$overwrite" ]; then
                rollBack "filebeat"
            else
                logger -e "Filebeat is already installed in this node or some of its files haven't been erased. Use option -o|--overwrite to overwrite all components."
                exit 1
            fi
        fi
    fi
}
