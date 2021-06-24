#!/bin/bash

# Program to build the Wazuh App for Splunk
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#
# CONFIGURATION VARIABLES
#

CURRENT_PATH=$( cd $(dirname $0) ; pwd -P )

BRANCH_TAG="$(sed -n "s/splunkapp=//p" ../VERSION)"
SPLUNK_VERSION=""
CONTAINER_NAME="wazuh-splunk-app-builder"
OUTDIR="${CURRENT_PATH}/output"
CHECKSUMDIR="${CURRENT_PATH}/output"
REVISION=""
REPOSITORY="wazuh-splunk"
CHECKSUM="no"

trap ctrl_c INT

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Optional] Select Git branch or tag. By default: ${BRANCH_TAG}"
    echo "    -s, --store <directory>   [Optional] Destination directory, by default a output folder will be created"
    echo "    -r, --revision            [Optional] Package revision that append to version e.g. x.x.x-y.y.y_rev"
    echo "    -c, --checksum <path>     [Optional] Generate checksum. By default: ${CHECKSUM}"
    echo "    -h, --help                Show this help."
    echo
    exit $1

}

build_package() {

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/

    # Build the Splunk package
    docker run -t --rm -v ${OUTDIR}:/wazuh_splunk_app:Z \
            -v ${CHECKSUMDIR}:/var/local/checksum:Z \
            ${CONTAINER_NAME} ${BRANCH_TAG} ${CHECKSUM} ${REVISION}

    return $?
}

clean(){

    exit_code=$1
    rm -rf ${SOURCES_DIRECTORY}
    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

main() {
    
    # Reading command line arguments
    while [ -n "$1" ]
    do
        case "$1" in
        "-h"|"--help")
            help 0
            ;;
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH_TAG="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-s"|"--store")
            if [ -n "$2" ]; then
                OUTDIR="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--revision")
            if [ -n "$2" ]; then
                REVISION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-c"|"--checksum")
            if [ -n "$2" ]; then
                CHECKSUMDIR="$2"
                CHECKSUM="yes"
                shift 2
            else
                CHECKSUM="yes"
                shift 1
            fi
            ;;
        *)
            help 1
        esac
    done

    build_package || clean 1
    clean 0

}

main "$@"
