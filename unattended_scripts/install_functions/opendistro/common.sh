# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"
kibana_wazuh_plugin="${repobaseurl}/ui/kibana/wazuh_kibana-${wazuh_version}_${elasticsearch_oss_version}-${wazuh_kibana_plugin_revision}.zip"

if [ -n "${development}" ]; then
    repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"
    repobaseurl="https://packages-dev.wazuh.com/pre-release"
    reporelease="unstable"
else
    repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
    repobaseurl="https://packages.wazuh.com/4.x"
    reporelease="stable"
fi

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

function createClusterKey() {
    openssl rand -hex 16 >> ${base_path}/certs/clusterkey
}

function changePasswords() {
    logger "Setting passwords."
    if [ -f "${base_path}/certs.tar" ]; then
        eval "tar -xf ${base_path}/certs.tar -C ${base_path} ./password_file.yml ${debug}"
        p_file="${base_path}/password_file.yml"
        checkInstalledPass
        if [ -n "${elasticsearch}" ] || [ -n "${AIO}" ]; then
            readUsers
        fi
        readFileUsers
    else 
        logger -e "Cannot find passwords-file. Exiting"
        exit 1
    fi
    if [ -n "${elasticsearch}" ] || [ -n "${AIO}" ]; then
        getNetworkHost
        createBackUp
        generateHash
    fi
    
    changePassword

    if [ -n "${elasticsearch}" ] || [ -n "${AIO}" ]; then
        runSecurityAdmin
    fi
    rm -rf ${p_file}
    logger "Passwords set."
}

function getConfig() {
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

function getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "$1" ]; then
            u_pass=${passwords[i]}
        fi
    done
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
