#!/bin/bash

# Wazuh-indexer securityadmin wrapper
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

HOST=""
INSTALL_PATH="/usr/share/wazuh-indexer"
CONFIG_PATH="/etc/wazuh-indexer"
OPTIONS="-icl -nhnv"
WAZUH_INDEXER_ROOT_CA="$(cat /etc/wazuh-indexer/opensearch.yml 2>&1 | grep http.pemtrustedcas | sed 's/.*: //')"
WAZUH_INDEXER_ADMIN_PATH="$(dirname "${WAZUH_INDEXER_ROOT_CA}" 2>&1)"
SECURITY_PATH="${INSTALL_PATH}/plugins/opensearch-security"
CONFIG_FILE="${CONFIG_PATH}/opensearch.yml"

# -----------------------------------------------------------------------------

getNetworkHost() {

    if [ -f "${CONFIG_FILE}" ]; then   
        HOST=$(grep -hr "network.host:" "${CONFIG_FILE}" 2>&1)
        NH="network.host: "
        HOST="${HOST//$NH}"

        # Allow to find ip with an interface
        PATTERN="^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"
        if [[ ! "${HOST}" =~ ${PATTERN} ]]; then
            interface="${HOST//_}"
            HOST=$(ip -o -4 addr list "${interface}" | awk '{print $4}' | cut -d/ -f1)
        fi

        if [ "${HOST}" = "0.0.0.0" ]; then
            HOST="127.0.0.1"
        fi
    fi

}

# -----------------------------------------------------------------------------
getPort() {

    if [ -f "${CONFIG_FILE}" ]; then
        PORT=$(grep -hr 'transport.tcp.port' "${CONFIG_FILE}" 2>&1)
        if [ "${PORT}" ]; then
            PORT=$(echo "${PORT}" | cut -d' ' -f2 | cut -d'-' -f1)
        else
            PORT="9300"
        fi
    fi

}
# -----------------------------------------------------------------------------

securityadmin() {

    getPort

    if [ ! -f "${CONFIG_FILE}" ]; then
        echo "ERROR: it was not possible to find ${CONFIG_FILE}"
        exit 1
    elif [ ! -d "${INSTALL_PATH}" ]; then
        echo "ERROR: it was not possible to find ${INSTALL_PATH}"
        exit 1
    elif [ ! -d "${SECURITY_PATH}" ]; then
        echo "ERROR: it was not possible to find ${SECURITY_PATH}"
        exit 1
    elif [ ! -d "${INSTALL_PATH}/jdk" ]; then
        echo "ERROR: it was not possible to find ${INSTALL_PATH}/jdk"
        exit 1
    elif [ ! -d "${CONFIG_PATH}" ]; then
        echo "ERROR: it was not possible to find ${CONFIG_PATH}"
        exit 1
    fi

    if [ -f "${WAZUH_INDEXER_ADMIN_PATH}/admin.pem" ] && [ -f "${WAZUH_INDEXER_ADMIN_PATH}/admin-key.pem" ] && [ -f "${WAZUH_INDEXER_ROOT_CA}" ]; then
        OPENSEARCH_PATH_CONF="${CONFIG_PATH}" JAVA_HOME="${INSTALL_PATH}/jdk" runuser wazuh-indexer --shell="/bin/bash" --command="${SECURITY_PATH}/tools/securityadmin.sh -cd ${SECURITY_PATH}/securityconfig -cacert ${WAZUH_INDEXER_ROOT_CA} -cert ${WAZUH_INDEXER_ADMIN_PATH}/admin.pem -key ${WAZUH_INDEXER_ADMIN_PATH}/admin-key.pem -h ${HOST} -p ${PORT} ${OPTIONS}"
    else
        echo "ERROR: this tool try to find admin.pem and admin-key.pem in ${WAZUH_INDEXER_ADMIN_PATH} but it couldn't. In this case, you must run manually the Indexer security initializer by running the command: JAVA_HOME="/usr/share/wazuh-indexer/jdk" runuser wazuh-indexer --shell="/bin/bash" --command="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/plugins/opensearch-security/plugins/opensearch-security/securityconfig -cacert /path/to/root-ca.pem -cert /path/to/admin.pem -key /path/to/admin-key.pem -h ${HOST} -p ${PORT} ${OPTIONS}" replacing /path/to/ by your certificates path."
        exit 1
    fi

}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -h, --host <host>     [Optional] Target IP or DNS to configure security."
    echo "    -p, --port <port>     [Optional] wazuh-indexer security port."
    echo "    --options <options>   [Optional] Custom securityadmin options."
    echo "    -h, --help            Show this help."
    echo
    exit "$1"
}


main() {

    getNetworkHost

    while [ -n "$1" ]
    do
        case "$1" in
        "-h"|"--help")
            help 0
            ;;
        "-h"|"--host")
            if [ -n "$2" ]; then
                HOST="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-p"|"--port")
            if [ -n "$2" ]; then
                PORT="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--options")
            if [ -n "$2" ]; then
                OPTIONS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    securityadmin

}

main "$@"
