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

# -----------------------------------------------------------------------------

getNetworkHost() {
    HOST=$(grep -hr "network.host:" "${CONFIG_PATH}"/opensearch.yml)
    NH="network.host: "
    HOST="${HOST//$NH}"

    # Allow to find ip with an interface
    if [[ "${HOST}" =~ _.*_ ]]; then
        interface="${HOST//_}"
        HOST=$(ip -o -4 addr list ${interface} | awk '{print $4}' | cut -d/ -f1)
    fi

    if [ "${HOST}" = "0.0.0.0" ]; then
        HOST="127.0.0.1"
    fi
}

# -----------------------------------------------------------------------------

PORT=$(grep -hr 'transport.tcp.port' "${CONFIG_PATH}/opensearch.yml")
if [ "${PORT}" ]; then
    PORT=$(echo ${PORT} | cut -d' ' -f2 | cut -d'-' -f1)
else
    PORT="9300"
fi

# -----------------------------------------------------------------------------

securityadmin() {
SECURITY_PATH="${INSTALL_PATH}/plugins/opensearch-security"

OPENSEARCH_PATH_CONF="${CONFIG_PATH}" JAVA_HOME="${INSTALL_PATH}/jdk" runuser wazuh-indexer --shell="/bin/bash" --command="${SECURITY_PATH}/tools/securityadmin.sh -cd ${SECURITY_PATH}/securityconfig -cacert ${CONFIG_PATH}/certs/root-ca.pem -cert ${CONFIG_PATH}/certs/admin.pem -key ${CONFIG_PATH}/certs/admin-key.pem -h ${HOST} -p ${PORT} ${OPTIONS}"

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
    exit $1
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
