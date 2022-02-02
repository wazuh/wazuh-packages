# Wazuh installer - common.sh functions. 
# Copyright (C) 2015, Wazuh Inc.
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

filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"
kibana_wazuh_plugin="${repobaseurl}/ui/kibana/wazuh_kibana-${wazuh_version}_${elasticsearch_oss_version}-${wazuh_kibana_plugin_revision}.zip"

function addWazuhrepo() {

    logger -d "Adding the Wazuh repository."

    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            eval "rm -f /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "rm -f /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "rm -f /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    fi

    if [ ! -f "/etc/yum.repos.d/wazuh.repo" ] && [ ! -f "/etc/zypp/repos.d/wazuh.repo" ] && [ ! -f "/etc/apt/sources.list.d/wazuh.list" ] ; then
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
        logger -d "Wazuh repository already exists. Skipping addition."
    fi
    logger -d "Wazuh repository added."

}

function createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "getConfig certificate/config_aio.yml ${base_path}/config.yml ${debug}"
    fi

    readConfig

    mkdir "${base_path}/certs"

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles

}

function createClusterKey() {

    openssl rand -hex 16 >> "${base_path}/certs/clusterkey"

}

function changePasswords() {

    logger -d "Setting passwords."
    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${base_path} ./password_file.yml ${debug}"
        p_file="${base_path}/password_file.yml"
        checkInstalledPass
        if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
            changeall=1
            readUsers
        fi
        readPasswordFileUsers
    else 
        logger -e "Cannot find passwords-file. Exiting"
        exit 1
    fi
    if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
        getNetworkHost
        createBackUp
        generateHash
    fi
    
    changePassword

    if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
        runSecurityAdmin
    fi
    rm -rf "${p_file}"

}

function extractConfig() {

    if ! $(tar -tf "${tar_file}" | grep -q config.yml); then
        logger -e "There is no config.yml file in ${tar_file}."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C ${base_path} ./config.yml ${debug}"

}

function getConfig() {

    if [ "$#" -ne 2 ]; then
        logger -e "getConfig should be called with two arguments"
        exit 1
    fi

    if [ -n "${local}" ]; then
        cp "${base_path}/${config_path}/${1}" "${2}"
    else
        curl -f -so "${2}" "${resources_config}/${1}"
    fi
    if [ "$?" != 0 ]; then
        logger -e "Unable to find configuration file ${1}. Exiting."
        rollBack
        exit 1
    fi

}

function getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${1}" ]; then
            u_pass=${passwords[i]}
        fi
    done

}

function installPrerequisites() {

    logger "Starting the installation of dependencies."

    openssl=""
    if [ -z "$(command -v openssl)" ]; then
        openssl="openssl"
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "yum install curl unzip wget libcap tar gnupg ${openssl} -y ${debug}"
    elif [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"
        eval "zypper -n install libcap-progs tar gnupg ${openssl} ${debug} || zypper -n install libcap2 tar gnupg ${openssl} ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt-get update -q ${debug}"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg ${openssl} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1
    else
        logger "Installation of dependencies finished."
    fi

}

function readPasswordFileUsers() {

    filecorrect=$(grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' "${p_file}")
    if [ "${filecorrect}" -ne 1 ]; then
        logger -e "The password file doesn't have a correct format.

It must have this format:
User:
  name: wazuh
  password: wazuhpassword
User:
  name: kibanaserver
  password: kibanaserverpassword"

	    exit 1
    fi

    sfileusers=$(grep name: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }')
    sfilepasswords=$(grep password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }')

    fileusers=(${sfileusers})
    filepasswords=(${sfilepasswords})

    if [ -n "${debugEnabled}" ]; then
        logger "Users in the file: ${fileusers[*]}"
        logger "Passwords in the file: ${filepasswords[*]}"
    fi

    if [ -n "${changeall}" ]; then
        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ ${users[i]} == "${fileusers[j]}" ]]; then
                    passwords[i]=${filepasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${elasticsearchinstalled}" ]; then
                logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done
    else
        finalusers=()
        finalpasswords=()

        if [ -n "${kibanainstalled}" ] &&  [ -n "${kibana}" ]; then 
            users=( kibanaserver admin )
        fi

        if [ -n "${filebeatinstalled}" ] && [ -n "${wazuh}" ]; then 
            users=( admin )
        fi

        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    finalusers+=(${fileusers[j]})
                    finalpasswords+=(${filepasswords[j]})
                    supported=true
                fi
            done
            if [ "${supported}" = "false" ] && [ -n "${elasticsearchinstalled}" ] && [ -n "${changeall}" ]; then
                logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done

        users=()
        users=(${finalusers[@]})
        passwords=(${finalpasswords[@]})
        changeall=1
    fi

}

function restoreWazuhrepo() {

    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ] && [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
            file="/etc/yum.repos.d/wazuh.repo"
        elif [ "${sys_type}" == "zypper" ] && [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
            file="/etc/zypp/repos.d/wazuh.repo"
        elif [ "${sys_type}" == "apt-get" ] && [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
            file="/etc/apt/sources.list.d/wazuh.list"
        else
            logger -w -d "Wazuh repository does not exists."
        fi
        eval "sed -i 's/-dev//g' ${file} ${debug}"
        eval "sed -i 's/pre-release/4.x/g' ${file} ${debug}"
        eval "sed -i 's/unstable/stable/g' ${file} ${debug}"
        logger -d "The Wazuh repository set to production."
    fi

}

function rollBack() {
    logger "Cleaning the installation."
	component=$1
    if [ -n "${AIO}" ] ; then
        component="all"
    fi
    if $component != "all"; then 
        eval "uninstall$component"
    else
        logger "Cleaning the installation. All packages and components will be uninstalled."
        eval "uninstallWazuh"
        eval "uninstallElasticsearch"
        eval "uninstallKibana"
    fi

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi
    logger "Cleaning the installation. Repositories were removed."

    if [ -z "${uninstall}" ]; then
        if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
            logger "Installation cleaned."
        else
            logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
    fi
}

function startService() {

    if [ "$#" -ne 1 ]; then
        logger -e "startService must be called with 1 argument."
        exit 1
    fi

    logger "Starting service ${1}."

    if ps -e | grep -E -q "^\ *1\ .*systemd$"; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    elif ps -e | grep -E -q "^\ *1\ .*init$"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} start ${debug}"
        eval "/etc/init.d/${1} start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1
        else
            logger "${1^} service started."
        fi     
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
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
