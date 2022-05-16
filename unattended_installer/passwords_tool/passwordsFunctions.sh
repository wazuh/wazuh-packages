# Passwords tool - library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function passwords_changePassword() {

    if [ -n "${changeall}" ]; then
        for i in "${!passwords[@]}"
        do
            if [ -n "${indexer_installed}" ] && [ -f "/usr/share/wazuh-indexer/backup/internal_users.yml" ]; then
                awk -v new=${hashes[i]} 'prev=="'${users[i]}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
            fi

            if [ "${users[i]}" == "admin" ]; then
                adminpass=${passwords[i]}
            elif [ "${users[i]}" == "kibanaserver" ]; then
                dashpass=${passwords[i]}
            fi

        done
    else
        if [ -n "${indexer_installed}" ] && [ -f "/usr/share/wazuh-indexer/backup/internal_users.yml" ]; then
            awk -v new="$hash" 'prev=="'${nuser}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
        fi

        if [ "${nuser}" == "admin" ]; then
            adminpass=${password}
        elif [ "${nuser}" == "kibanaserver" ]; then
            dashpass=${password}
        fi

    fi

    if [ "${nuser}" == "admin" ] || [ -n "${changeall}" ]; then
        if [ -n "${filebeat_installed}" ]; then
            if [ -n "$(filebeat keystore list | grep password)" ];then
                eval "echo ${adminpass} | filebeat keystore add password --force --stdin ${debug}"
            else
                wazuhold=$(grep "password:" /etc/filebeat/filebeat.yml )
                ra="  password: "
                wazuhold="${wazuhold//$ra}"
                conf="$(awk '{sub("password: .*", "password: '${adminpass}'")}1' /etc/filebeat/filebeat.yml)"
                echo "${conf}" > /etc/filebeat/filebeat.yml
            fi
            passwords_restartService "filebeat"
        fi
    fi

    if [ "$nuser" == "kibanaserver" ] || [ -n "$changeall" ]; then
        if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
            if [ -n "$(/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root list | grep opensearch.password)" ]; then
                eval "echo ${dashpass} | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password ${debug_pass}"
            else
                wazuhdashold=$(grep "password:" /etc/wazuh-dashboard/opensearch_dashboards.yml )
                rk="opensearch.password: "
                wazuhdashold="${wazuhdashold//$rk}"
                conf="$(awk '{sub("opensearch.password: .*", "opensearch.password: '${dashpass}'")}1' /etc/wazuh-dashboard/opensearch_dashboards.yml)"
                echo "${conf}" > /etc/wazuh-dashboard/opensearch_dashboards.yml
            fi
            passwords_restartService "wazuh-dashboard"
        fi
    fi

}

function passwords_checkUser() {

    for i in "${!users[@]}"; do
        if [ "${users[i]}" == "${nuser}" ]; then
            exists=1
        fi
    done

    if [ -z "${exists}" ]; then
        common_logger -e "The given user does not exist"
        exit 1;
    fi

}

function passwords_createBackUp() {

    if [ -z "${indexer_installed}" ] && [ -z "${dashboard_installed}" ] && [ -z "${filebeat_installed}" ]; then
        common_logger -e "Cannot find Wazuh indexer, Wazuh dashboard or Filebeat on the system."
        exit 1;
    else
        if [ -n "${indexer_installed}" ]; then
            capem=$(grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml )
            rcapem="plugins.security.ssl.transport.pemtrustedcas_filepath: "
            capem="${capem//$rcapem}"
            if [[ -z "${adminpem}" ]] || [[ -z "${adminkey}" ]]; then
                passwords_readAdmincerts
            fi
        fi
    fi

    common_logger -d "Creating password backup."
    eval "mkdir /usr/share/wazuh-indexer/backup ${debug}"
    eval "JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -icl -p 9300 -backup /usr/share/wazuh-indexer/backup -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -h ${IP} ${debug}"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        common_logger -e "The backup could not be created"
        exit 1;
    fi
    common_logger -d "Password backup created in /usr/share/wazuh-indexer/backup."

}

function passwords_generateHash() {

    if [ -n "${changeall}" ]; then
        common_logger -d "Generating password hashes."
        for i in "${!passwords[@]}"
        do
            nhash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${passwords[i]}" | grep -v WARNING)
            if [  "${PIPESTATUS[0]}" != 0  ]; then
                common_logger -e "Hash generation failed."
                exit 1;
            fi
            hashes+=("${nhash}")
        done
        common_logger -d "Password hashes generated."
    else
        common_logger "Generating password hash"
        hash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p ${password} | grep -v WARNING)
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "Hash generation failed."
            exit 1;
        fi
        common_logger -d "Password hash generated."
    fi

}

function passwords_generatePassword() {

    if [ -n "${nuser}" ]; then
        common_logger -d "Generating random password."
        password=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c${1:-32};echo;)
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "The password could not been generated."
            exit 1;
        fi
    else
        common_logger -d "Generating random passwords."
        for i in "${!users[@]}"; do
            PASS=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c${1:-32};echo;)
            passwords+=("${PASS}")
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "The password could not been generated."
                exit 1;
            fi
        done
    fi
}

function passwords_generatePasswordFile() {

    users=( admin kibanaserver kibanaro logstash readall snapshotrestore wazuh_admin wazuh_user )
    user_description=(
        "Admin user for the web user interface and Wazuh indexer. Use this user to log in to Wazuh dashboard"
        "Wazuh dashboard user for establishing the connection with Wazuh indexer"
        "Regular Dashboard user, only has read permissions to all indices and all permissions on the .kibana index"
        "Filebeat user for CRUD operations on Wazuh indices"
        "User with READ access to all indices"
        "User with permissions to perform snapshot and restore operations"
        "Admin user used to communicate with Wazuh API"
        "Regular user to query Wazuh API"
    )
    passwords_generatePassword
    for i in "${!users[@]}"; do
        echo "# ${user_description[${i}]}" >> "${gen_file}"
        echo "  username: ${users[${i}]}" >> "${gen_file}"
        echo "  password: ${passwords[${i}]}" >> "${gen_file}"
        echo ""	>> "${gen_file}"
    done
    passwords_createPasswordAPI

}

function passwords_getNetworkHost() {
    IP=$(grep -hr "network.host:" /etc/wazuh-indexer/opensearch.yml)
    NH="network.host: "
    IP="${IP//$NH}"

    #allow to find ip with an interface
    if [[ ${IP} =~ _.*_ ]]; then
        interface="${IP//_}"
        IP=$(ip -o -4 addr list ${interface} | awk '{print $4}' | cut -d/ -f1)
    fi

    if [ ${IP} == "0.0.0.0" ]; then
        IP="localhost"
    fi
}

function passwords_readAdmincerts() {

    if [[ -f /etc/wazuh-indexer/certs/admin.pem ]]; then
        adminpem="/etc/wazuh-indexer/certs/admin.pem"
    else
        common_logger -e "No admin certificate indicated. Please run the script with the option -c <path-to-certificate>."
        exit 1;
    fi

    if [[ -f /etc/wazuh-indexer/certs/admin-key.pem ]]; then
        adminkey="/etc/wazuh-indexer/certs/admin-key.pem"
    elif [[ -f /etc/wazuh-indexer/certs/admin.key ]]; then
        adminkey="/etc/wazuh-indexer/certs/admin.key"
    else
        common_logger -e "No admin certificate key indicated. Please run the script with the option -k <path-to-key-certificate>."
        exit 1;
    fi

}

function passwords_readFileUsers() {
    filecorrect=$(grep -Ev '^#|^\s*$' "${p_file}" | grep -Pzc '\A(\s*username:[ \t]+\w+\s*password:[ \t]+[A-Za-z0-9.*+?()[{\|]+\s*)+\Z')
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The password file doesn't have a correct format.

It must have this format:

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

    if [ -n "${changeall}" ]; then
        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords[i]=${filepasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The given user ${fileusers[j]} does not exist"
            fi
        done
    else
        finalusers=()
        finalpasswords=()

        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    finalusers+=("${fileusers[j]}")
                    finalpasswords+=("${filepasswords[j]}")
                    supported=true
                fi
            done
            if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The given user ${fileusers[j]} does not exist"
            fi
        done

        users=()
        passwords=()
        users=(${finalusers[@]})
        passwords=(${finalpasswords[@]})
        changeall=1
    fi

}

function passwords_readUsers() {

    susers=$(grep -B 1 hash: /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml | grep -v hash: | grep -v "-" | awk '{ print substr( $0, 1, length($0)-1 ) }')
    users=($susers)

}

function passwords_restartService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "passwords_restartService must be called with 1 argument."
        exit 1
    fi

    if ps -e | grep -E -q "^\ *1\ .*systemd$"; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl restart ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started"
        fi
    elif ps -e | grep -E -q "^\ *1\ .*init$"; then
        eval "/etc/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started"
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started"
        fi
    else
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1;
    fi

}

function passwords_runSecurityAdmin() {

    common_logger -d "Loading new passwords changes."
    eval "cp /usr/share/wazuh-indexer/backup/* /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ ${debug}"
    eval "OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -p 9300 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${IP} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "Could not load the changes."
        exit 1;
    fi
    eval "rm -rf /usr/share/wazuh-indexer/backup/ ${debug}"

    if [[ -n "${nuser}" ]] && [[ -n ${autopass} ]]; then
        common_logger -nl $'\nThe password for user '${nuser}' is '${password}''
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
    fi

    if [[ -n "${nuser}" ]] && [[ -z ${autopass} ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
    fi

    if [ -n "${changeall}" ]; then
        if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
            for i in "${!users[@]}"; do
                common_logger -nl $'The password for user '${users[i]}' is '${passwords[i]}''
            done
            common_logger -w "Passwords changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
        else
            common_logger -d "Passwords changed."
        fi
    fi

}

function passwords_createPasswordAPI() {

    password_wazuh=$(tr -dc 'A-Za-z0-9.*+?()[{\|' </dev/urandom | head -c"${1:-32}";echo;)
    password_wazuh_wui=$(tr -dc 'A-Za-z0-9.*+?()[{\|' </dev/urandom | head -c"${1:-32}";echo;)

    echo "# New password for wazuh API" >> "${gen_file}"
    echo "  username: wazuh" >> "${gen_file}"
    echo "  password: $password_wazuh" >> "${gen_file}"
    echo ""	>> "${gen_file}"
    echo "# New password for wazuh-wui API" >> "${gen_file}"
    echo "  username: wazuh_wui" >> "${gen_file}"
    echo "  password: $password_wazuh_wui" >> "${gen_file}"
    echo ""	>> "${gen_file}"

}
