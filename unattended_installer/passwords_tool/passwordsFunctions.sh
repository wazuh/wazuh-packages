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
                awk -v new="${hashes[i]}" 'prev=="'"${users[i]}"':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
            fi

            if [ "${users[i]}" == "admin" ]; then
                adminpass=${passwords[i]}
            elif [ "${users[i]}" == "kibanaserver" ]; then
                dashpass=${passwords[i]}
            fi

        done
    else
        if [ -n "${indexer_installed}" ] && [ -f "/usr/share/wazuh-indexer/backup/internal_users.yml" ]; then
            awk -v new="$hash" 'prev=="'"${nuser}"':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
        fi

        if [ "${nuser}" == "admin" ]; then
            adminpass=${password}
        elif [ "${nuser}" == "kibanaserver" ]; then
            dashpass=${password}
        fi

    fi

    if [ "${nuser}" == "admin" ] || [ -n "${changeall}" ]; then
        if [ -n "${filebeat_installed}" ]; then
            if filebeat keystore list | grep -q password ; then
                eval "echo ${adminpass} | filebeat keystore add password --force --stdin ${debug}"
            else
                wazuhold=$(grep "password:" /etc/filebeat/filebeat.yml )
                ra="  password: "
                wazuhold="${wazuhold//$ra}"
                conf="$(awk '{sub("password: .*", "password: '"${adminpass}"'")}1' /etc/filebeat/filebeat.yml)"
                echo "${conf}" > /etc/filebeat/filebeat.yml
            fi
            passwords_restartService "filebeat"
        fi
    fi

    if [ "$nuser" == "kibanaserver" ] || [ -n "$changeall" ]; then
        if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
            if /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root list | grep -q opensearch.password; then
                eval "echo ${dashpass} | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password ${debug_pass}"
            else
                wazuhdashold=$(grep "password:" /etc/wazuh-dashboard/opensearch_dashboards.yml )
                rk="opensearch.password: "
                wazuhdashold="${wazuhdashold//$rk}"
                conf="$(awk '{sub("opensearch.password: .*", "opensearch.password: '"${dashpass}"'")}1' /etc/wazuh-dashboard/opensearch_dashboards.yml)"
                echo "${conf}" > /etc/wazuh-dashboard/opensearch_dashboards.yml
            fi
            passwords_restartService "wazuh-dashboard"
        fi
    fi

}

function passwords_changePasswordApi() {
    #Change API password tool
    if [ -n "${changeall}" ]; then
        for i in "${!api_passwords[@]}"; do
            if [ -n "${wazuh_installed}" ]; then
                passwords_getApiUserId "${api_users[i]}"
                WAZUH_PASS_API='{"password":"'"${api_passwords[i]}"'"}'
                eval 'curl -s -k -X PUT -H "Authorization: Bearer $TOKEN_API" -H "Content-Type: application/json" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null'
                if [ "${api_users[i]}" == "${adminUser}" ]; then
                    sleep 1
                    adminPassword="${api_passwords[i]}"
                    passwords_getApiToken
                fi
                if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                    common_logger -nl $"The password for Wazuh API user ${api_users[i]} is ${api_passwords[i]}"
                fi
            fi
            if [ "${api_users[i]}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
                passwords_changeDashboardApiPassword "${api_passwords[i]}"
            fi
        done
    else
        if [ -n "${wazuh_installed}" ]; then
            passwords_getApiUserId "${nuser}"
            WAZUH_PASS_API='{"password":"'"${password}"'"}'
            eval 'curl -s -k -X PUT -H "Authorization: Bearer $TOKEN_API" -H "Content-Type: application/json" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null'
            if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                common_logger -nl $"The password for Wazuh API user ${nuser} is ${password}"
            fi
        fi
        if [ "${nuser}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
                passwords_changeDashboardApiPassword "${password}"
        fi
    fi
}

function passwords_changeDashboardApiPassword() {

    j=0
    until [ -n "${file_exists}" ] || [ "${j}" -eq "12" ]; do
        if [ -f "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml" ]; then
            eval "sed -i 's|password: .*|password: \"${1}\"|g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
            if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
                common_logger "Updated wazuh-wui user password in wazuh dashboard. Remember to restart the service."
            fi
            file_exists=1
        fi
        sleep 5
        j=$((j+1))
    done

}

function passwords_checkUser() {

    if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
        for i in "${!api_users[@]}"; do
            if [ "${api_users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    else
        for i in "${!users[@]}"; do
            if [ "${users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    fi

    if [ -z "${exists}" ]; then
        common_logger -e "The given user does not exist"
        exit 1;
    fi

}

function passwords_checkPassword() {

    if ! echo "$1" | grep -q "[A-Z]" || ! echo "$1" | grep -q "[a-z]" || ! echo "$1" | grep -q "[0-9]" || ! echo "$1" | grep -q "[.*+?-]" || [ "${#1}" -lt 8 ] || [ "${#1}" -gt 64 ]; then
        common_logger -e "The password must have a length between 8 and 64 characters and contain at least one upper and lower case letter, a number and a symbol(.*+?-)."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
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
        hash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${password}" | grep -v WARNING)
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
        pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
        special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
        minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
        mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
        number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
        password="$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "The password could not been generated."
            exit 1;
        fi
    else
        common_logger -d "Generating random passwords."
        for i in "${!users[@]}"; do
            pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
            special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
            minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
            mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
            number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
            passwords+=("$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')")
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "The password could not been generated."
                exit 1;
            fi
        done
        for i in "${!api_users[@]}"; do
            pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
            special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
            minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
            mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
            number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
            api_passwords+=("$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')")
            if [ "${PIPESTATUS[0]}" != 0 ]; then
                common_logger -e "The password could not been generated."
                exit 1;
            fi
        done
    fi
}

function passwords_generatePasswordFile() {

    users=( admin kibanaserver kibanaro logstash readall snapshotrestore )
    api_users=( wazuh wazuh-wui )
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
    api_user_description=(
        "Password for wazuh API user"
        "Password for wazuh-wui API user"
    )
    passwords_generatePassword

    for i in "${!users[@]}"; do
        {
        echo "# ${user_description[${i}]}"
        echo "  indexer_username: '${users[${i}]}'" 
        echo "  indexer_password: '${passwords[${i}]}'" 
        echo ""	
        } >> "${gen_file}"
    done

    for i in "${!api_users[@]}"; do
        {
        echo "# ${api_user_description[${i}]}" 
        echo "  api_username: '${api_users[${i}]}'" 
        echo "  api_password: '${api_passwords[${i}]}'"
        echo ""	
        } >> "${gen_file}"
    done

}

function passwords_getApiToken() {

    retries=0
    max_internal_error_retries=10

    TOKEN_API="$(common_curl -s -u \"${adminUser}\":\"${adminPassword}\" -k -X POST \"https://localhost:55000/security/user/authenticate?raw=true\" --max-time 300 --retry 5 --retry-delay 5)"
    while [[ "${TOKEN_API}" =~ "Wazuh Internal Error" ]] && [ "${retries}" -lt "${max_internal_error_retries}" ]
    do
        TOKEN_API="$(common_curl -s -u \"${adminUser}\":\"${adminPassword}\" -k -X POST \"https://localhost:55000/security/user/authenticate?raw=true\" --max-time 300 --retry 5 --retry-delay 5)"
        retries=$((retries+1))
        sleep 1
    done
    if [[ ${TOKEN_API} =~ "Wazuh Internal Error" ]]; then
        common_logger -e "There was an error while trying to get the API token."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    fi
    if [[ ${TOKEN_API} =~ "Invalid credentials" ]]; then
        common_logger -e "Invalid admin user credentials"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    fi

}

function passwords_getApiUsers() {

    mapfile -t api_users < <(curl -s -k -X GET -H "Authorization: Bearer $TOKEN_API" -H "Content-Type: application/json"  "https://localhost:55000/security/users?pretty=true" | grep username | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")

}

function passwords_getApiIds() {

    mapfile -t api_ids < <(curl -s -k -X GET -H "Authorization: Bearer $TOKEN_API" -H "Content-Type: application/json"  "https://localhost:55000/security/users?pretty=true" | grep id | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")

}

function passwords_getApiUserId() {

    user_id="noid"
    for u in "${!api_users[@]}"; do
        if [ "${1}" == "${api_users[u]}" ]; then
            user_id="${api_ids[u]}"
        fi
    done

    if [ "${user_id}" == "noid" ]; then
        common_logger -e "User ${1} is not registered in Wazuh API"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
    fi

}


function passwords_getNetworkHost() {

    IP=$(grep -hr "network.host:" /etc/wazuh-indexer/opensearch.yml)
    NH="network.host: "
    IP="${IP//$NH}"

    #allow to find ip with an interface
    if [[ ${IP} =~ _.*_ ]]; then
        interface="${IP//_}"
        IP=$(ip -o -4 addr list "${interface}" | awk '{print $4}' | cut -d/ -f1)
    fi

    if [ "${IP}" == "0.0.0.0" ]; then
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

    filecorrect=$(grep -Ev '^#|^\s*$' "${p_file}" | grep -Pzc "\A(\s*(indexer_username|api_username|indexer_password|api_password):[ \t]+[\'\"]?[\w.*+?-]+[\'\"]?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The password file does not have a correct format or password uses invalid characters. Allowed characters: A-Za-z0-9.*+?

For Wazuh indexer users, the file must have this format:

# Description
  indexer_username: <user>
  indexer_password: <password>

For Wazuh API users, the file must have this format:

# Description
  api_username: <user>
  api_password: <password>

"
	    exit 1
    fi

    sfileusers=$(grep indexer_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfilepasswords=$(grep indexer_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")

    sfileapiusers=$(grep api_username: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")
    sfileapipasswords=$(grep api_password: "${p_file}" | awk '{ print substr( $2, 1, length($2) ) }' | sed -e "s/[\'\"]//g")

    mapfile -t fileusers <<< "${sfileusers}"
    mapfile -t filepasswords <<< "${sfilepasswords}"

    mapfile -t fileapiusers <<< "${sfileapiusers}"
    mapfile -t fileapipasswords <<< "${sfileapipasswords}"

    if [ -n "${changeall}" ]; then
        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    passwords[i]=${filepasswords[j]}
                    supported=true
                fi
            done
            if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The user ${fileusers[j]} does not exist"
            fi
        done

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
            for j in "${!fileapiusers[@]}"; do
                supported=false
                for i in "${!api_users[@]}"; do
                    if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                        passwords_checkPassword "${fileapipasswords[j]}"
                        api_passwords[i]=${fileapipasswords[j]}
                        supported=true
                    fi
                done
                if [ "${supported}" = false ] && [ -n "${indexer_installed}" ]; then
                    common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
                fi
            done
        fi
    else
        finalusers=()
        finalpasswords=()

        finalapiusers=()
        finalapipasswords=()

        for j in "${!fileusers[@]}"; do
            supported=false
            for i in "${!users[@]}"; do
                if [[ "${users[i]}" == "${fileusers[j]}" ]]; then
                    passwords_checkPassword "${filepasswords[j]}"
                    finalusers+=("${fileusers[j]}")
                    finalpasswords+=("${filepasswords[j]}")
                    supported=true
                fi
            done
            if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                common_logger -e "The user ${fileusers[j]} does not exist"
            fi
        done

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
            for j in "${!fileapiusers[@]}"; do
                supported=false
                for i in "${!api_users[@]}"; do
                    if [[ "${api_users[i]}" == "${fileapiusers[j]}" ]]; then
                        passwords_checkPassword "${fileapipasswords[j]}"
                        finalapiusers+=("${fileapiusers[j]}")
                        finalapipasswords+=("${fileapipasswords[j]}")
                        supported=true
                    fi
                done
                if [ ${supported} = false ] && [ -n "${indexer_installed}" ]; then
                    common_logger -e "The Wazuh API user ${fileapiusers[j]} does not exist"
                fi
            done
        fi

        users=()
        passwords=()
        mapfile -t users < <(printf "%s\n" "${finalusers[@]}")
        mapfile -t passwords < <(printf "%s\n" "${finalpasswords[@]}")
        mapfile -t api_users < <(printf "%s\n" "${finalapiusers[@]}")
        mapfile -t api_passwords < <(printf "%s\n" "${finalapipasswords[@]}")
        
        changeall=1
    fi

}

function passwords_readUsers() {

    susers=$(grep -B 1 hash: /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml | grep -v hash: | grep -v "-" | awk '{ print substr( $0, 1, length($0)-1 ) }')
    mapfile -t users <<< "${susers[@]}"

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
            common_logger -d "${1} started."
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
            common_logger -d "${1} started."
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
            common_logger -d "${1} started."
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
        common_logger -nl "The password for user ${nuser} is ${password}"
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
    fi

    if [[ -n "${nuser}" ]] && [[ -z ${autopass} ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
    fi

    if [ -n "${changeall}" ]; then
        if [ -z "${AIO}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ] && [ -z "${wazuh}" ] && [ -z "${start_indexer_cluster}" ]; then
            for i in "${!users[@]}"; do
                common_logger -nl "The password for user ${users[i]} is ${passwords[i]}"
            done
            common_logger -w "Wazuh indexer passwords changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services."
        else
            common_logger -d "Passwords changed."
        fi
    fi

}
