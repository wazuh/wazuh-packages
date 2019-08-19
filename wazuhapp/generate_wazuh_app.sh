#!/bin/bash

# Program to build the Wazuh App for Kibana
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH=$( cd $(dirname $0) ; pwd -P )

CONTAINER_NAME="wazuh-app:latest"
REVISION=""
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
OUTDIR="${CURRENT_PATH}/output/"
CHECKSUMDIR=""
WAZUH_VERSION=""
KIBANA_VERSION=""

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8-6.7 or v3.7.2-6.5.4"
    echo "    -s, --store <path>        [Optional] Set the destination path of package, by defauly /tmp/wazuh-app."
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
    docker run --rm -t  -v ${SOURCES_DIRECTORY}:/source \
        -v "${OUTDIR}":/wazuh_app \
        -v ${CHECKSUMDIR}:/var/local/checksum \
        ${CONTAINER_NAME} ${WAZUH_VERSION} ${KIBANA_VERSION} ${REVISION} ${CHECKSUM}

    if [ "$?" = "0" ]; then
        clean 0
    else
        clean 1
    fi
    return 0
}

compute_version_revision(){

    cd "${SOURCES_DIRECTORY}"

    WAZUH_VERSION=$(python -c 'import json; f=open("package.json"); pkg=json.load(f); f.close(); print(pkg["version"])')
    KIBANA_VERSION=$(python -c 'import json; f=open("package.json"); pkg=json.load(f); f.close(); print(pkg["kibana"]["version"])')

    cd -

    return 0
}

download_sources(){

    git clone https://github.com/wazuh/wazuh-kibana-app -b ${BRANCH_TAG} --depth=1 ${SOURCES_DIRECTORY}

    compute_version_revision
}
clean(){

    exit_code=$1
    rm -rf ${SOURCES_DIRECTORY}
    exit ${exit_code}
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

        if download_sources; then
            build_package
            clean 0
        else
            clean 1
        fi

    else
        help 1
    fi
}

main "$@"