#!/bin/bash

# Wazuh-indexer securityadmin wrapper
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

HOST="127.0.0.1"
INSTALL_PATH="/usr/share/wazuh-indexer"
CONFIG_PATH="/etc/wazuh-indexer"
OPTIONS="-icl -nhnv"
PORT="9800"

securityadmin() {
SECURITY_PATH="${INSTALL_PATH}/plugins/opensearch-security"

OPENSEARCH_PATH_CONF="${CONFIG_PATH}" JAVA_HOME="${INSTALL_PATH}/jdk" runuser wazuh-indexer --shell="/bin/bash" --command="${SECURITY_PATH}/tools/securityadmin.sh -cd ${SECURITY_PATH}/securityconfig -cacert ${CONFIG_PATH}/certs/root-ca.pem -cert ${CONFIG_PATH}/certs/admin.pem -key ${CONFIG_PATH}/certs/admin-key.pem -h ${HOST} -p ${PORT} ${OPTIONS}"

}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -h, --host <host>     [Optional] Target IP or DNS to configure security."
    echo "    -p, --port <port>     [Optional] wazuh-indexer security port, by default ${PORT}."
    echo "    --options <options>   [Optional] Custom securityadmin options."
    echo "    -h, --help            Show this help."
    echo
    exit $1
}


main() {
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
