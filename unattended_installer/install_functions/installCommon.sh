# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function installCommon_cleanExit() {

    rollback_conf=""

    if [ -n "$spin_pid" ]; then
        eval "kill -9 $spin_pid ${debug}"
    fi

    until [[ "${rollback_conf}" =~ ^[N|Y|n|y]$ ]]; do
        echo -ne "\nDo you want to clean the ongoing installation?[Y/N]"
        read -r rollback_conf
    done
    if [[ "${rollback_conf}" =~ [N|n] ]]; then
        exit 1
    else
        installCommon_rollBack
        exit 1
    fi

}

function installCommon_spin() {

    trap "{ tput el1; exit 0; }" 15
    spinner="/|\\-/|\\-"
    trap "echo ''" EXIT
    while :
    do
        for i in $(seq 0 7)
        do
            echo -n "${spinner:$i:1}"
            echo -en "\010"
            sleep 0.1
        done
    done
}

function installCommon_addWazuhRepo() {

    common_logger -d "Adding the Wazuh repository."

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
            eval "chmod 644 /etc/yum.repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "rpm --import ${repogpg} ${debug}"
            eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\${releasever} - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"
            eval "chmod 644 /etc/zypp/repos.d/wazuh.repo ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
            eval "echo \"deb ${repobaseurl}/apt/ ${reporelease} main\" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
            eval "apt-get update -q ${debug}"
            eval "chmod 644 /etc/apt/sources.list.d/wazuh.list ${debug}"
        fi
    else
        common_logger -d "Wazuh repository already exists. Skipping addition."
    fi

    if [ -n "${development}" ]; then
        common_logger "Wazuh development repository added."
    else
        common_logger "Wazuh repository added."
    fi

}

function installCommon_createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig certificate/config_aio.yml ${config_file} ${debug}"
    fi

    cert_readConfig

    if [ -d /tmp/wazuh-certificates/ ]; then
        eval "rm -rf /tmp/wazuh-certificates/ ${debug}"
    fi        
    mkdir "/tmp/wazuh-certificates/ ${debug}"
    

    cert_generateRootCAcertificate
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateFilebeatcertificates
    cert_generateDashboardcertificates
    cert_cleanFiles
    eval "mv /tmp/wazuh-certificates/* /tmp/wazuh-install-files ${debug}"
    eval "rm -rf /tmp/wazuh-certificates/ ${debug}"

}

function installCommon_createClusterKey() {

    openssl rand -hex 16 >> "/tmp/wazuh-install-files/clusterkey"

}

function installCommon_createInstallFiles() {
    
    if [ -d /tmp/wazuh-install-files ]; then
        eval "rm -rf /tmp/wazuh-install-files ${debug}"
    fi 
    
    if mkdir /tmp/wazuh-install-files > /dev/null 2>&1; then
        common_logger "Generating configuration files."
        if [ -n "${configurations}" ]; then
            cert_checkOpenSSL
        fi
        installCommon_createCertificates
        if [ -n "${server_node_types[*]}" ]; then
            installCommon_createClusterKey
        fi
        gen_file="/tmp/wazuh-install-files/passwords.wazuh"
        passwords_generatePasswordFile
        # Using cat instead of simple cp because OpenSUSE unknown error.
        eval "cat '${config_file}' > '/tmp/wazuh-install-files/config.yml'"
        eval "chown root:root /tmp/wazuh-install-files/*"
        eval "tar -zcf '${tar_file}' -C '/tmp/' wazuh-install-files/ ${debug}"
        eval "rm -rf '/tmp/wazuh-install-files' ${debug}"
        common_logger "Created ${tar_file_name}. It contains Wazuh cluster key, certificates, and passwords necessary for installation."
    else
        common_logger -e "Unable to create /tmp/wazuh-install-files"
        exit 1
    fi
}

function installCommon_changePasswords() {

    common_logger -d "Setting passwords."
    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${base_path} wazuh-install-files/passwords.wazuh ${debug}"
        p_file="${base_path}/wazuh-install-files/passwords.wazuh"
        common_checkInstalled
        if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
            changeall=1
            passwords_readUsers
        fi
        installCommon_readPasswordFileUsers
    else
        common_logger -e "Cannot find passwords file. Exiting"
        exit 1
    fi
    if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
        passwords_getNetworkHost
        passwords_createBackUp
        passwords_generateHash
    fi

    passwords_changePassword

    if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
        passwords_runSecurityAdmin
    fi
    rm -rf "${base_path}/wazuh-install-files"

}

function installCommon_extractConfig() {

    if ! $(tar -tf "${tar_file}" | grep -q wazuh-install-files/config.yml); then
        common_logger -e "There is no config.yml file in ${tar_file}."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C ${base_path} wazuh-install-files/config.yml ${debug}"
    eval "mv ${base_path}/wazuh-install-files/config.yml ${base_path}/config.yml"

}

function installCommon_getConfig() {

    if [ "$#" -ne 2 ]; then
        common_logger -e "installCommon_getConfig should be called with two arguments"
        exit 1
    fi

    config_name="config_file_$(eval "echo ${1} | sed 's|/|_|g;s|.yml||'")"
    if [ -z "$(eval "echo \${${config_name}}")" ]; then
        common_logger -e "Unable to find configuration file ${1}. Exiting."
        installCommon_rollBack
        exit 1
    fi
    eval "echo \"\${${config_name}}\"" > "${2}"
}

function installCommon_getPass() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${1}" ]; then
            u_pass=${passwords[i]}
        fi
    done

}

function installCommon_installPrerequisites() {

    if [ "${sys_type}" == "yum" ]; then
        dependencies=( curl unzip wget libcap tar gnupg openssl )
        not_installed=()
        for dep in "${dependencies[@]}"; do
            if [ -z "$(yum list installed 2>/dev/null | grep ${dep})" ];then
                not_installed+=("${dep}")
            fi
        done

        if [ "${#not_installed[@]}" -gt 0 ]; then
            common_logger "--- Dependencies ---"
            for dep in "${not_installed[@]}"; do
                common_logger "Installing $dep."
                eval "yum install ${dep} -y ${debug}"
                if [  "$?" != 0  ]; then
                    common_logger -e "Cannot install dependency: ${dep}."
                    exit 1
                fi
            done
        fi

    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt update -q ${debug}"
        dependencies=( apt-transport-https curl unzip wget libcap2-bin tar software-properties-common gnupg openssl )
        not_installed=()

        for dep in "${dependencies[@]}"; do
            if [ -z "$(apt list --installed 2>/dev/null | grep ${dep})" ];then
                not_installed+=("${dep}")
            fi
        done

        if [ "${#not_installed[@]}" -gt 0 ]; then
            common_logger "--- Dependencies ----"
            for dep in "${not_installed[@]}"; do
                common_logger "Installing $dep."
                eval "DEBIAN_FRONTEND=noninteractive apt install ${dep} -y ${debug}"
                if [  "$?" != 0  ]; then
                    common_logger -e "Cannot install dependency: ${dep}."
                    exit 1
                fi
            done
        fi
    fi

}

function installCommon_readPasswordFileUsers() {

    filecorrect=$(grep -Ev '^#|^\s*$' "${p_file}" | grep -Pzc '\A(\s*username:[ \t]+\w+\s*password:[ \t]+[A-Za-z0-9_\-]+\s*)+\Z')
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The password file doesn't have a correct format.

# Description
  username: name
  password: password

# Wazuh indexer admin user
  username: kibanaserver
  password: NiwXQw82pIf0dToiwczduLBnUPEvg7T0

"

	    exit 1
    fi

    sfileusers=$(grep username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }')
    sfilepasswords=$(grep password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }')

    fileusers=(${sfileusers})
    filepasswords=(${sfilepasswords})

    if [ -n "${debugEnabled}" ]; then
        common_logger "Users in the file: ${fileusers[*]}"
        common_logger "Passwords in the file: ${filepasswords[*]}"
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
            if [ "${supported}" = false ] && [ -n "${indexerinstalled}" ]; then
                common_logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done
    else
        finalusers=()
        finalpasswords=()

        if [ -n "${dashboardinstalled}" ] &&  [ -n "${dashboard}" ]; then
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
            if [ "${supported}" = "false" ] && [ -n "${indexerinstalled}" ] && [ -n "${changeall}" ]; then
                common_logger -e -d "The given user ${fileusers[j]} does not exist"
            fi
        done

        users=()
        users=(${finalusers[@]})
        passwords=(${finalpasswords[@]})
        changeall=1
    fi

}

function installCommon_restoreWazuhrepo() {

    if [ -n "${development}" ]; then
        if [ "${sys_type}" == "yum" ] && [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
            file="/etc/yum.repos.d/wazuh.repo"
        elif [ "${sys_type}" == "zypper" ] && [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
            file="/etc/zypp/repos.d/wazuh.repo"
        elif [ "${sys_type}" == "apt-get" ] && [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
            file="/etc/apt/sources.list.d/wazuh.list"
        else
            common_logger -w -d "Wazuh repository does not exists."
        fi
        eval "sed -i 's/-dev//g' ${file} ${debug}"
        eval "sed -i 's/pre-release/4.x/g' ${file} ${debug}"
        eval "sed -i 's/unstable/stable/g' ${file} ${debug}"
        common_logger -d "The Wazuh repository set to production."
    fi

}

function installCommon_rollBack() {

    if [ -z "${uninstall}" ]; then
        common_logger "--- Removing existing Wazuh installation ---"
    fi

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi

    if [[ -n "${wazuhinstalled}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
        common_logger "Removing Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-manager -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-manager ${debug}"
            eval "rm -f /etc/init.d/wazuh-manager ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-manager -y ${debug}"
        fi
        common_logger "Wazuh manager removed."
    fi

    if [[ ( -n "${wazuh_remaining_files}"  || -n "${wazuhinstalled}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [[ -n "${indexerinstalled}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh indexer."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-indexer -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-indexer ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-indexer -y ${debug}"
        fi
        common_logger "Wazuh indexer removed."
    fi

    if [[ ( -n "${indexer_remaining_files}" || -n "${indexerinstalled}" ) && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
        eval "rm -rf /usr/share/wazuh-indexer/ ${debug}"
        eval "rm -rf /etc/wazuh-indexer/ ${debug}"
    fi

    if [[ -n "${filebeatinstalled}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Filebeat."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug}"
        fi
        common_logger "Filebeat removed."
    fi

    if [[ ( -n "${filebeat_remaining_files}" || -n "${filebeatinstalled}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [[ -n "${dashboardinstalled}" && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh dashboard."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-dashboard -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-dashboard ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-dashboard -y ${debug}"
        fi
        common_logger "Wazuh dashboard removed."
    fi

    if [[ ( -n "${dashboard_remaining_files}" || -n "${dashboardinstalled}" ) && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-dashboard/ ${debug}"
        eval "rm -rf /usr/share/wazuh-dashboard/ ${debug}"
        eval "rm -rf /etc/wazuh-dashboard/ ${debug}"
        eval "rm -rf /run/wazuh-dashboard/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/wazuh-indexer/"
                            "/var/log/filebeat/"
                            "/etc/systemd/system/opensearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                            "/etc/systemd/system/multi-user.target.wants/filebeat.service"
                            "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-dashboard.service"
                            "/etc/systemd/system/wazuh-dashboard.service"
                            "/lib/firewalld/services/dashboard.xml"
                            "/lib/firewalld/services/opensearch.xml"
                            "${base_path}/wazuh-install-files"
                            "${base_path}/wazuh-install-files.tar" )

    eval "rm -rf ${elements_to_remove[*]}"

    if [ -z "${uninstall}" ]; then
        if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
            common_logger "Installation cleaned."
        else
            common_logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
    fi

}

function installCommon_startService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_startService must be called with 1 argument."
        exit 1
    fi

    common_logger "Starting service ${1}."

    if ps -e | grep -E -q "^\ *1\ .*systemd$"; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "$?" != 0  ]; then
            common_logger -e "${1^} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1^} service started."
        fi
    elif ps -e | grep -E -q "^\ *1\ .*init$"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} start ${debug}"
        eval "/etc/init.d/${1} start ${debug}"
        if [  "$?" != 0  ]; then
            common_logger -e "${1^} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1^} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "$?" != 0  ]; then
            common_logger -e "${1^} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1^} service started."
        fi
    else
        common_logger -e "${1^} could not start. No service manager found on the system."
        exit 1
    fi

}
