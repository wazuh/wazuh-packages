#!/bin/bash

# Program to build the Wazuh App for Kibana
# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH=$( cd $(dirname $0) ; pwd -P )

REVISION=""
BRANCH_TAG=""
CHECKSUMDIR=""
CONTAINER_NAME="wazuh-kibana-app-builder"
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
OUTDIR="${CURRENT_PATH}/output/"

trap ctrl_c INT

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8-6.7 or v3.7.2-6.5.4"
    echo "    -s, --store <path>        [Optional] Set the destination path of package, by default /tmp/wazuh-app."
    echo "    -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev"
    echo "    -c, --checksum <path>     [Optional] Generate checksum"
    echo "    -h, --help                Show this help."
    echo
    exit $1
}

build_package(){

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/
    # Build the Wazuh Kibana app package using the build docker image
    docker run --rm -t -v "${OUTDIR}":/wazuh_app:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        ${CONTAINER_NAME} ${BRANCH_TAG} ${CHECKSUM} ${REVISION}

    return $?
}

clean(){

    exit_code=$1
    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

main(){
    CHECKSUM="no"
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                HAVE_BRANCH=true
                BRANCH_TAG="$(echo "$2" | cut -d "/" -f2)"
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
        "-h"|"--help")
            help 0
            ;;
        *)
            help 0
        esac
    done

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${OUTDIR}"
    fi

    if [[ ${HAVE_BRANCH} == true ]]; then
        build_package || clean 1
        clean 0
    else
        help 1
    fi
}

main "$@"
