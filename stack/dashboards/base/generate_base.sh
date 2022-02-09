#!/bin/bash

# Wazuh package generator
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e


reference=""
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
DOCKERFILE_PATH="${CURRENT_PATH}/docker"
CONTAINER_NAME="dashboards_base_builder"
OPENSEARCH_VERSION="1.2.0"
OUTDIR="${CURRENT_PATH}/output"
REVISION="1"

# -----------------------------------------------------------------------------

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.xz,*-dashboards-*}
    
    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

# -----------------------------------------------------------------------------

build() {

    # Copy the necessary files
    cp ${CURRENT_PATH}/builder.sh ${DOCKERFILE_PATH}

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1

    if [ "${reference}" ];then
        docker run -t --rm -v ${OUTDIR}/:/tmp/output:Z \
            ${CONTAINER_NAME} ${OPENSEARCH_VERSION} ${REVISION} ${reference} || return 1
    else
        docker run -t --rm -v ${OUTDIR}/:/tmp/output:Z \
            -v ${CURRENT_PATH}/../../..:/root:Z \
            ${CONTAINER_NAME} ${OPENSEARCH_VERSION} ${REVISION} || return 1
    fi

    echo "Base file $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -v, --version <path>         [Optional] The OpenSearch-dashboards Version. By default, 1.2.0"
    echo "    --reference <ref>     [Required] wazuh-packages branch or tag"
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}

# -----------------------------------------------------------------------------

main() {
    while [ -n "$1" ]
    do
        case "$1" in
        "-h"|"--help")
            help 0
            ;;
        "-s"|"--store")
            if [ -n "$2" ]; then
                OUTDIR="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-v"|"--version")
            if [ -n "$2" ]; then
                OPENSEARCH_VERSION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--reference")
            if [ -n "${2}" ]; then
                reference="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    build || clean 1

    clean 0
}

main "$@"