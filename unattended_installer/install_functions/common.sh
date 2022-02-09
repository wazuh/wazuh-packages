# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

if [ -n "${development}" ]; then
    readonly repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"
    readonly repobaseurl="https://packages-dev.wazuh.com/pre-release"
    readonly reporelease="unstable"
else
    readonly repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
    readonly repobaseurl="https://packages.wazuh.com/4.x"
    readonly reporelease="stable"
fi

readonly filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
readonly filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"

function common_addWazuhRepo() {

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
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\${releasever} - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\${releasever} - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"
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

function common_createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "common_getConfig certificate/config_aio.yml ${base_path}/config.yml ${debug}"
    fi

    readConfig

    mkdir "${base_path}/certs"

    generateRootCAcertificate
    generateAdmincertificate
    generateIndexercertificates
    generateFilebeatcertificates
    generateDashboardscertificates
    cleanFiles

}

function common_createClusterKey() {

    openssl rand -hex 16 >> "${base_path}/certs/clusterkey"

}

function common_changePasswords() {

    logger -d "Setting passwords."
    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${base_path} ./password_file.yml ${debug}"
        p_file="${base_path}/password_file.yml"
        checkInstalledPass
        if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
            changeall=1
            readUsers
        fi
        common_readPasswordFileUsers
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

function common_extractConfig() {

    if ! $(tar -tf "${tar_file}" | grep -q config.yml); then
        logger -e "There is no config.yml file in ${tar_file}."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C ${base_path} ./config.yml ${debug}"

}

function common_getConfig() {

    if [ "$#" -ne 2 ]; then
        logger -e "common_getConfig should be called with two arguments"
        exit 1
    fi

    if [ -n "${local}" ]; then
        cp "${base_path}/${config_path}/${1}" "${2}"
    else
        curl -f -so "${2}" "${resources_config}/${1}"
    fi
    if [ "$?" != 0 ]; then
        logger -e "Unable to find configuration file ${1}. Exiting."
        common_rollBack
        exit 1
    fi

}

function common_getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${1}" ]; then
            u_pass=${passwords[i]}
        fi
    done

}

function common_installPrerequisites() {

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
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin tar software-properties-common gnupg ${openssl} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed, probably due to the OS repositories. Please check them."
        exit 1
    else
        logger "Installation of dependencies finished."
    fi

}

function common_readPasswordFileUsers() {

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
            if [ "${supported}" = false ] && [ -n "${indexerchinstalled}" ]; then
                logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done
    else
        finalusers=()
        finalpasswords=()

        if [ -n "${dashboardsinstalled}" ] &&  [ -n "${dashboards}" ]; then
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
            if [ "${supported}" = "false" ] && [ -n "${indexerchinstalled}" ] && [ -n "${changeall}" ]; then
                logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done

        users=()
        users=(${finalusers[@]})
        passwords=(${finalpasswords[@]})
        changeall=1
    fi

}

function common_restoreWazuhrepo() {

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

function common_rollBack() {

    componentList=("${wazuhinstalled}" "${filebeatinstalled}" "${elasticsearchinstalled}" "${kibanainstalled}")

    logger "Analyzing components to uninstall and clean."

    # Uninstall case: manager
    if [ -n "${AIO}" ] || [ "${uninstall_component_name}" == "all" ] || [ "${uninstall_component_name}" == "manager" ]; then
        if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ]; then
            manager_uninstall
        else
            logger "Wazuh manager components were not found on the system so it was not uninstalled."
        fi
    fi
    # Uninstall case: indexer
    if [ -n "${AIO}" ] || [ "${uninstall_component_name}" == "all" ] || [ "${uninstall_component_name}" == "elasticsearch" ]; then
        if [ -n "${indexerchinstalled}" ] || [ -n "${elastic_remaining_files}" ]; then
            indexer_uninstall
        else

            logger "Wazuh indexer components were not found on the system so it was not uninstalled."
        fi
    fi
    # Uninstall case: dashboard
    if [ -n "${AIO}" ] || [ ${uninstall_component_name} == "all" ] || [ ${uninstall_component_name} == "kibana" ] ; then
        if [ -n "${dashboardsinstalled}" ] || [ -n "${dashboards_remaining_files}" ]; then
            dashboards_uninstall
        else
            logger "Wazuh dashboards components were not found on the system so it was not uninstalled."
        fi
    fi

    # Overwrite case
    if [ -n "${overwrite}" ] && [ -n "${wazuh}" ]; then
        manager_uninstall
    fi
    if [ -n "${overwrite}" ] && [ -n "${indexer}" ]; then
        indexer_uninstall
    fi
    if [ -n "${overwrite}" ] && [ -n "${dashboards}" ]; then
        uninstallkibana
    fi

    # rollBack case
    for component in "${componentList[@]}"; do
        if [ "${component}" == "manager" ] || [ "${component}" == "elastichsearch" ] || [ "${component}" == "kibana" ] ; then
            eval "uninstall$component"
        fi
    done

    checkIfInstalled

    if [ -n "${wazuhinstalled}" ] || [ -n "${wazuh_remaining_files}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${filebeat_remaining_files}" ] || [ -n "${elasticsearchinstalled}" ] || [ -n "${elastic_remaining_files}" ] || [ -n "${kibanainstalled}" ] || [ -n "${kibana_remaining_files}" ]; then
        logger -w "Some Wazuh components are still installed on this host."
    else
        rollBackRepositories
    fi

    if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
        logger "Installation cleaned."
    fi

    if [ -z "${uninstall}" ]; then
        logger "Check the ${logfile} file to learn more about the issue."
    fi

    logger "The uninstall process is complete."
}

function rollBackRepositories() {

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
        deleteRepositorie="true"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
        deleteRepositorie="true"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
        deleteRepositorie="true"
    fi

    if [ -n "${deleteRepositorie}" ]; then
        logger "Repositories were removed."
    fi

}

function common_startService() {

    if [ "$#" -ne 1 ]; then
        logger -e "common_startService must be called with 1 argument."
        exit 1
    fi

    logger "Starting service ${1}."

    if ps -e | grep -E -q "^\ *1\ .*systemd$"; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            common_rollBack
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
            common_rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            common_rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    else
        logger -e "${1^} could not start. No service manager found on the system."
        exit 1
    fi

}
