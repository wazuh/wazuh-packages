#!/bin/bash

# Program to build the Wazuh App for Splunk
# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#
# CONFIGURATION VARIABLES
#

CURRENT_PATH=$( cd $(dirname $0) ; pwd -P )

BRANCH_TAG=""
SPLUNK_VERSION=""
CONTAINER_NAME="wazuh-splunk-app-builder"
OUTDIR="${CURRENT_PATH}/output"
CHECKSUMDIR=""
REVISION=""
REPOSITORY="wazuh-splunk"

trap ctrl_c INT

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8 or v3.8.1-7.2.3"
    echo "    -s, --store <directory>   [Optional] Destination directory by default ${CURRENT_PATH}/output"
    echo "    -r, --revision            [Optional] Package revision that append to version e.g. x.x.x-y.y.y_rev"
    echo "    -c, --checksum <path>     [Optional] Generate checksum"
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
    CHECKSUM="no"
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
                HAVE_BRANCH=true
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

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${OUTDIR}"
    fi

    if [[ "$HAVE_BRANCH" == true ]] ; then
        build_package || clean 1
        clean 0
    else
        help 1
    fi
}

main "$@"
