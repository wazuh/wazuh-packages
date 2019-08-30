#!/bin/bash

# Program to build the Wazuh App for Kibana
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
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
READY_TO_RELEASE=""
CONTAINER_NAME="wazuh-splunk-app:latest"
OUTDIR="${CURRENT_PATH}/output/"
CHECKSUMDIR=""
REVISION=" "
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
REPOSITORY="wazuh-splunk"
WAZUH_VERSION=""

help() {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8 or v3.8.1-7.2.3"
    echo "    -s, --store <directory>   [Optional] Destination directory by default /tmp/splunk-app"
    echo "    -r, --revision            [Optional] Package revision that append to version e.g. x.x.x-y.y.y-rev"
    echo "    -c, --checksum  <path>    [Optional] Generate checksum"
    echo "    -h, --help                Show this help."
    echo
    exit $1

}

build_package() {

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/
    # Run Docker and build package

    docker run -t --rm -v ${SOURCES_DIRECTORY}:/pkg \
            -v ${OUTDIR}:/wazuh_splunk_app \
            -v ${CHECKSUMDIR}:/var/local/checksum \
            ${CONTAINER_NAME} ${WAZUH_VERSION} ${SPLUNK_VERSION} ${REVISION} ${CHECKSUM}


    if [ "$?" = "0" ]; then
        clean 0
    else
        clean 1
    fi
    return 0
}

compute_version_revision() {

    WAZUH_VERSION=$(cat ${SOURCES_DIRECTORY}/SplunkAppForWazuh/default/package.conf | grep version -m 1  | cut -d' ' -f 3)
    SPLUNK_VERSION=$(cat ${SOURCES_DIRECTORY}/SplunkAppForWazuh/default/package.conf | grep version -m 3  | cut -d ' ' -f 3| head -n 3 | tail -1)

    return 0
}

download_source() {

    if git clone https://github.com/wazuh/${REPOSITORY} -b ${BRANCH_TAG} ${SOURCES_DIRECTORY} --depth=1; then
        compute_version_revision
    else
        echo "Error: Source code from ${BRANCH_TAG} could not be downloaded"
        exit 1
    fi

    return 0
}

clean(){

    exit_code=$1
    rm -rf ${SOURCES_DIRECTORY}
    exit ${exit_code}
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
                    BRANCH_TAG="$(echo $2 | cut -d'/' -f2)"
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
        if ! download_source ; then
            clean 1
        fi
        build_package
        clean 0
    else
        help 1
    fi
}

main "$@"
