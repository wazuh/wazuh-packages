# Certificate tool - Library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


function cert_cleanFiles() {

    eval "rm -f ${base_path}/certs/*.csr ${debug}"
    eval "rm -f ${base_path}/certs/*.srl ${debug}"
    eval "rm -f ${base_path}/certs/*.conf ${debug}"
    eval "rm -f ${base_path}/certs/admin-key-temp.pem ${debug}"

}

function cert_checkOpenSSL() {
    if [ -z "$(command -v openssl)" ]; then
        common_logger -e "OpenSSL not installed."
        exit 1
    fi
}

function cert_generateAdmincertificate() {

    eval "openssl genrsa -out ${base_path}/certs/admin-key-temp.pem 2048 ${debug}"
    eval "openssl pkcs8 -inform PEM -outform PEM -in ${base_path}/certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${base_path}/certs/admin-key.pem ${debug}"
    eval "openssl req -new -key ${base_path}/certs/admin-key.pem -out ${base_path}/certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Wazuh/CN=admin' ${debug}"
    eval "openssl x509 -days 3650 -req -in ${base_path}/certs/admin.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -sha256 -out ${base_path}/certs/admin.pem ${debug}"
    eval "chmod 444 ${base_path}/certs/admin*.pem ${debug}"

}

function cert_generateCertificateconfiguration() {

    cat > "${base_path}/certs/${1}.conf" <<- EOF
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = req_distinguished_name
        x509_extensions = v3_req

        [req_distinguished_name]
        C = US
        L = California
        O = Wazuh
        OU = Wazuh
        CN = cname

        [ v3_req ]
        authorityKeyIdentifier=keyid,issuer
        basicConstraints = CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        IP.1 = cip
	EOF

    conf="$(awk '{sub("CN = cname", "CN = '${1}'")}1' "${base_path}/certs/${1}.conf")"
    echo "${conf}" > "${base_path}/certs/${1}.conf"

    isIP=$(echo "${2}" | grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    isDNS=$(echo "${2}" | grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" )

    if [[ -n "${isIP}" ]]; then
        conf="$(awk '{sub("IP.1 = cip", "IP.1 = '${2}'")}1' "${base_path}/certs/${1}.conf")"
        echo "${conf}" > "${base_path}/certs/${1}.conf"
    elif [[ -n "${isDNS}" ]]; then
        conf="$(awk '{sub("CN = cname", "CN =  '${2}'")}1' "${base_path}/certs/${1}.conf")"
        echo "${conf}" > "${base_path}/certs/${1}.conf"
        conf="$(awk '{sub("IP.1 = cip", "DNS.1 = '${2}'")}1' "${base_path}/certs/${1}.conf")"
        echo "${conf}" > "${base_path}/certs/${1}.conf"
    else
        common_logger -e "The given information does not match with an IP address or a DNS."
        exit 1
    fi

}

function cert_generateIndexercertificates() {

    if [ ${#indexer_node_names[@]} -gt 0 ]; then
        common_logger -d "Creating the Wazuh indexer certificates."

        for i in "${!indexer_node_names[@]}"; do
            cert_generateCertificateconfiguration "${indexer_node_names[i]}" "${indexer_node_ips[i]}"
            eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${indexer_node_names[i]}-key.pem -out ${base_path}/certs/${indexer_node_names[i]}.csr -config ${base_path}/certs/${indexer_node_names[i]}.conf -days 3650 ${debug}"
            eval "openssl x509 -req -in ${base_path}/certs/${indexer_node_names[i]}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${indexer_node_names[i]}.pem -extfile ${base_path}/certs/${indexer_node_names[i]}.conf -extensions v3_req -days 3650 ${debug}"
            eval "chmod 444 ${base_path}/certs/${indexer_node_names[i]}-key.pem ${debug}"
        done
    fi

}

function cert_generateFilebeatcertificates() {

    if [ ${#server_node_names[@]} -gt 0 ]; then
        common_logger -d "Creating the Wazuh server certificates."

        for i in "${!server_node_names[@]}"; do
            cert_generateCertificateconfiguration "${server_node_names[i]}" "${server_node_ips[i]}"
            eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${server_node_names[i]}-key.pem -out ${base_path}/certs/${server_node_names[i]}.csr -config ${base_path}/certs/${server_node_names[i]}.conf -days 3650 ${debug}"
            eval "openssl x509 -req -in ${base_path}/certs/${server_node_names[i]}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${server_node_names[i]}.pem -extfile ${base_path}/certs/${server_node_names[i]}.conf -extensions v3_req -days 3650 ${debug}"
        done
    fi
    
}

function cert_generateDashboardcertificates() {

    if [ ${#dashboard_node_names[@]} -gt 0 ]; then
        common_logger -d "Creating the Wazuh dashboard certificates."

        for i in "${!dashboard_node_names[@]}"; do
            cert_generateCertificateconfiguration "${dashboard_node_names[i]}" "${dashboard_node_ips[i]}"
            eval "openssl req -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/${dashboard_node_names[i]}-key.pem -out ${base_path}/certs/${dashboard_node_names[i]}.csr -config ${base_path}/certs/${dashboard_node_names[i]}.conf -days 3650 ${debug}"
            eval "openssl x509 -req -in ${base_path}/certs/${dashboard_node_names[i]}.csr -CA ${base_path}/certs/root-ca.pem -CAkey ${base_path}/certs/root-ca.key -CAcreateserial -out ${base_path}/certs/${dashboard_node_names[i]}.pem -extfile ${base_path}/certs/${dashboard_node_names[i]}.conf -extensions v3_req -days 3650 ${debug}"
            eval "chmod 444 ${base_path}/certs/${dashboard_node_names[i]}-key.pem ${debug}"
        done
    fi

}

function cert_generateRootCAcertificate() {

    common_logger -d "Creating the root certificate."

    eval "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ${base_path}/certs/root-ca.key -out ${base_path}/certs/root-ca.pem -batch -subj '/OU=Wazuh/O=Wazuh/L=California/' -days 3650 ${debug}"

}

function cert_parseYaml() {

    local prefix=${2}
    local s='[[:space:]]*'
    local w='[a-zA-Z0-9_]*'
    local fs=$(echo @|tr @ '\034')
    sed -ne "s|^\($s\):|\1|" \
            -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
            -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  ${1} |
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

function cert_readConfig() {

    if [ -f "${config_file}" ]; then
        if [ ! -s "${config_file}" ]; then
            common_logger -e "File ${config_file} is empty"
            exit 1
        fi
        eval "$(cert_parseYaml "${config_file}")"
        eval "indexer_node_names=( $(cert_parseYaml "${config_file}" | grep nodes_indexer_name | sed 's/nodes_indexer_name=//') )"
        eval "server_node_names=( $(cert_parseYaml "${config_file}" | grep nodes_server_name | sed 's/nodes_server_name=//') )"
        eval "dashboard_node_names=( $(cert_parseYaml "${config_file}" | grep nodes_dashboard_name | sed 's/nodes_dashboard_name=//') )"

        eval "indexer_node_ips=( $(cert_parseYaml "${config_file}" | grep nodes_indexer_ip | sed 's/nodes_indexer_ip=//') )"
        eval "server_node_ips=( $(cert_parseYaml "${config_file}" | grep nodes_server_ip | sed 's/nodes_server_ip=//') )"
        eval "dashboard_node_ips=( $(cert_parseYaml "${config_file}" | grep nodes_dashboard_ip | sed 's/nodes_dashboard_ip=//') )"

        eval "server_node_types=( $(cert_parseYaml "${config_file}" | grep nodes_server_node_type | sed 's/nodes_server_node_type=//') )"

        unique_names=($(echo "${indexer_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#indexer_node_names[@]}" ]; then 
            common_logger -e "Duplicated indexer node names."
            exit 1
        fi

        unique_ips=($(echo "${indexer_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#indexer_node_ips[@]}" ]; then 
            common_logger -e "Duplicated indexer node ips."
            exit 1
        fi

        unique_names=($(echo "${server_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#server_node_names[@]}" ]; then 
            common_logger -e "Duplicated Wazuh server node names."
            exit 1
        fi

        unique_ips=($(echo "${server_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#server_node_ips[@]}" ]; then 
            common_logger -e "Duplicated Wazuh server node ips."
            exit 1
        fi

        unique_names=($(echo "${dashboard_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_names[@]}" -ne "${#dashboard_node_names[@]}" ]; then
            common_logger -e "Duplicated dashboard node names."
            exit 1
        fi

        unique_ips=($(echo "${dashboard_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${#unique_ips[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
            common_logger -e "Duplicated dashboard node ips."
            exit 1
        fi

        if [ "${#server_node_names[@]}" -ne "${#server_node_ips[@]}" ]; then 
            common_logger -e "Different number of Wazuh server node names and IPs."
            exit 1
        fi

        for i in "${server_node_types[@]}"; do
            if ! echo "$i" | grep -ioq master && ! echo "$i" | grep -ioq worker; then
                common_logger -e "Incorrect node_type $i must be master or worker"
                exit 1
            fi
        done

        if [ "${#server_node_names[@]}" -le 1 ]; then
            if [ "${#server_node_types[@]}" -ne 0 ]; then
                common_logger -e "The tag node_type can only be used with more than one Wazuh server."
                exit 1
            fi
        elif [ "${#server_node_names[@]}" -gt "${#server_node_types[@]}" ]; then
            common_logger -e "The tag node_type needs to be specified for all Wazuh server nodes."
            exit 1
        elif [ "${#server_node_names[@]}" -lt "${#server_node_types[@]}" ]; then
            common_logger -e "Found extra node_type tags."
            exit 1
        elif [ $(grep -io master <<< ${server_node_types[*]} | wc -l) -ne 1 ]; then
            common_logger -e "Wazuh cluster needs a single master node."
            exit 1
        elif [ $(grep -io worker <<< ${server_node_types[*]} | wc -l) -ne $(( ${#server_node_types[@]} - 1 )) ]; then
            common_logger -e "Incorrect number of workers."
            exit 1
        fi

        if [ "${#dashboard_node_names[@]}" -ne "${#dashboard_node_ips[@]}" ]; then
            common_logger -e "Different number of dashboard node names and IPs."
            exit 1
        fi

    else
        common_logger -e "No configuration file found. ${config_file}."
        exit 1
    fi

}
