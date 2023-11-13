#!/bin/bash

# Program to build the Wazuh App for OpenSearch Dashboards
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
CONTAINER_NAME="wazuh-plugin-for-opensearch-dashboards-builder"
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
OUTDIR="${CURRENT_PATH}/output/"

trap ctrl_c INT

help() {
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Build Wazuh plugin files."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") -b | -s | -r | -c | -h"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -b, --branch <branch>"
    echo -e "                [Required] Select Git branch or tag."
    echo -e ""
    echo -e "        -s, --store <path>"
    echo -e "                [Optional] Set the destination path of package, by default /tmp/wazuh-app."
    echo -e ""
    echo -e "        -r, --revision <rev>"
    echo -e "                [Optional] Package revision."
    echo -e ""
    echo -e "        -c, --checksum <path>"
    echo -e "                [Optional] Generate checksum."
    echo -e ""
    echo -e "        -h, --help"
    echo -e "                Show this help."
    echo -e ""
    exit $1
}

build_package(){

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/
    # Build the Wazuh plugin for OpenSearch Dashboards package using the build docker image
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
