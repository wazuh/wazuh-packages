#!/bin/bash
# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function common_cleanExit() {

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
        common_rollBack
        exit 1
    fi

}

function common_spin() {

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

function logger() {
    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    disableHeader=
    if [ -n "${1}" ]; then
        while [ -n "${1}" ]; do
            case ${1} in
                "-e")
                    mtype="ERROR:"
                    shift 1
                    ;;
                "-w")
                    mtype="WARNING:"
                    shift 1
                    ;;
                "-d")
                    debugLogger=1
                    shift 1
                    ;;
                *)
                    message="${1}"
                    shift 1
                    ;;
            esac
        done
    fi

    if [ -z "${debugLogger}" ] || ( [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ] ); then
            echo "${now} ${mtype} ${message}" | tee -a ${logfile}
    fi
}

function common_getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -e <elasticsearch-node-name> | -k <kibana-node-name> | -s | -w <wazuh-node-name>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                All-In-One installation."
    echo -e ""
    echo -e "        -c,  --create-configurations"
    echo -e "                Creates configurations.tar file containing config.yml, certificates, passwords and cluster key."
    echo -e ""
    echo -e "        -d,  --development"
    echo -e "                Uses development repository."
    echo -e ""
    echo -e "        -ds,  --disable-spinner"
    echo -e "                Disables the spinner indicator."
    echo -e ""
    echo -e ""
    echo -e "        -f,  --fileconfig <path-to-config-yml>"
    echo -e "                Path to config file. By default: ${base_path}/config.yml"
    echo -e ""
    echo -e "        -F,  --force-dashboards"
    echo -e "                Ignore indexer cluster related errors in kibana installation"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -i,  --ignore-health-check"
    echo -e "                Ignores the health-check."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Starts the indexer cluster."
    echo -e ""
    echo -e "        -t,  --tar <path-to-certs-tar>"
    echo -e "                Path to tar containing certificate files. By default: ${base_path}/configurations.tar"
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstalls all Wazuh components. NOTE: This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboards <dashboards-node-name>"
    echo -e "                Wazuh dashboards installation."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer <indexer-node-name>"
    echo -e "                Wazuh indexer installation."
    echo -e ""
    echo -e "        -ws,  --wazuh-server <wazuh-node-name>"
    echo -e "                Wazuh server installation. It includes Filebeat."
    exit 1

}

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

    cert_readConfig

    mkdir "${base_path}/certs"

    cert_generateRootCAcertificate
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateFilebeatcertificates
    cert_generateDashboardcertificates
    cert_cleanFiles

}

function common_createClusterKey() {

    openssl rand -hex 16 >> "${base_path}/certs/clusterkey"

}

function common_changePasswords() {

    logger -d "Setting passwords."
    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${base_path} ./password_file.yml ${debug}"
        p_file="${base_path}/password_file.yml"
        passwords_checkInstalledPass
        if [ -n "${start_elastic_cluster}" ] || [ -n "${AIO}" ]; then
            changeall=1
            passwords_readUsers
        fi
        common_readPasswordFileUsers
    else
        logger -e "Cannot find passwords_file. Exiting"
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

    config_name="config_file_$(eval "echo ${1} | sed 's|/|_|g;s|.yml||'")"
    if [ -z "$(eval "echo \${${config_name}}")" ]; then
        logger -e "Unable to find configuration file ${1}. Exiting."
        common_rollBack
        exit 1
    fi
    eval "echo \"\${${config_name}}\"" > "${2}"
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
        eval "DEBIAN_FRONTEND=noninteractive apt install apt-transport-https curl unzip wget libcap2-bin tar software-properties-common gnupg ${openssl} -y ${debug}"
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
            if [ "${supported}" = false ] && [ -n "${indexerinstalled}" ]; then
                logger -e -d "The given user ${fileusers[j]} does not exist"
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

    if [ -z "${uninstall}" ]; then
        logger "Cleaning the installation."
    fi

    if [ -f "/etc/yum.repos.d/wazuh.repo" ]; then
        eval "rm /etc/yum.repos.d/wazuh.repo"
    elif [ -f "/etc/zypp/repos.d/wazuh.repo" ]; then
        eval "rm /etc/zypp/repos.d/wazuh.repo"
    elif [ -f "/etc/apt/sources.list.d/wazuh.list" ]; then
        eval "rm /etc/apt/sources.list.d/wazuh.list"
    fi

    if [[ -n "${wazuhinstalled}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
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

    if [[ ( -n "${wazuh_remaining_files}"  || -n "${wazuhinstalled}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [[ -n "${indexerinstalled}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        logger -w "Removing Wazuh indexer."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-indexer -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-indexer ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge ^wazuh-indexer -y ${debug}"
        fi
    fi

    if [[ ( -n "${indexer_remaining_files}" || -n "${indexerinstalled}" ) && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
        eval "rm -rf /usr/share/wazuh-indexer/ ${debug}"
        eval "rm -rf /etc/wazuh-indexer/ ${debug}"
    fi

    if [[ -n "${filebeatinstalled}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        logger -w "Removing Filebeat."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug}"
        fi
    fi

    if [[ ( -n "${filebeat_remaining_files}" || -n "${filebeatinstalled}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [[ -n "${dashboardinstalled}" && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        logger -w "Removing Wazuh dashboard."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-dashboard -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-dashboard ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-dashboard -y ${debug}"
        fi
    fi

    if [[ ( -n "${dashboard_remaining_files}" || -n "${dashboardinstalled}" ) && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-dashboard/ ${debug}"
        eval "rm -rf /usr/share/wazuh-dashboard/ ${debug}"
        eval "rm -rf /etc/wazuh-dashboard/ ${debug}"
        eval "rm -rf /run/wazuh-dashboard/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/elasticsearch/"
                            "/var/log/filebeat/"
                            "/etc/systemd/system/opensearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                            "/etc/systemd/system/multi-user.target.wants/filebeat.service"
                            "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-dashboard.service"
                            "/etc/systemd/system/wazuh-dashboard.service"
                            "/lib/firewalld/services/dashboard.xml"
                            "/lib/firewalld/services/opensearch.xml" )

    eval "rm -rf ${elements_to_remove[*]}"

    if [ -z "${uninstall}" ]; then
        if [ -n "${srollback_conf}" ] || [ -n "${overwrite}" ]; then
            logger "Installation cleaned."
        else
            logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
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
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
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
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            common_rollBack
            exit 1
        else
            logger "${1^} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
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
