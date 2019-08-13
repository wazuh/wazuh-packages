#!/bin/bash

# Program to build the Wazuh App for Kibana
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CONTAINER_NAME="wazuh-app:latest"
DESTINATION="/tmp/wazuh-app"
REVISION=""
TMP_DIR="/tmp/build_wazuhapp/app/"

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8-6.7 or v3.7.2-6.5.4"
    echo "    -s, --store <path>        [Optional] Set the destination path of package, by defauly /tmp/wazuh-app."
    echo "    -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev"
    echo "    -k, --checksum            [Optional] Generate checksum"
    echo "    -h, --help                Show this help."
    echo
    exit $1
}

build_package(){

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/
    # Build the Wazuh Kibana app package using the build docker image
    docker run --rm -t  -v ${TMP_DIR}:/source -v "${DESTINATION}":/wazuh_app ${CONTAINER_NAME} ${WAZUH_VERSION} \
        ${KIBANA_VERSION} ${APP_REVISION} ${CHECKSUM}

    if [ "$?" = "0" ]; then
        delete_sources 0
    else
        delete_sources 1
    fi
    return 0
}

compute_version_revision(){

  WAZUH_VERSION=$(python -c 'import json; f=open("package.json"); pkg=json.load(f); f.close(); print(pkg["version"])')
  APP_REVISION=$REVISION
  KIBANA_VERSION=$(python -c 'import json; f=open("package.json"); pkg=json.load(f); f.close(); print(pkg["kibana"]["version"])')

  return 0
}

download_sources(){

    git clone https://github.com/wazuh/wazuh-kibana-app -b ${BRANCH_TAG} --depth=1 ${TMP_DIR}
    cd "${TMP_DIR}"
    compute_version_revision
    cd -
}
delete_sources(){

    exit_code=$1
    rm -rf ${TMP_DIR}
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
            if [ -n "$2" ]
            then
                if [[ "${2: -1}" != "/" ]]; then
                DESTINATION="$2/"
                else
                DESTINATION="$2"
                fi
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
        "-k" | "--checksum")
            CHECKSUM="yes"
            shift 1
            ;;
        "-h"|"--help")
            help 0
            ;;
        *)
            help 0
        esac
    done

    if [[ ${HAVE_BRANCH} == true ]]; then

        if download_sources; then
            build_package
            delete_sources 0
        else
            delete_sources 1
        fi

    else
        help 1
    fi
}

main "$@"