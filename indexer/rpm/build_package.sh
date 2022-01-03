#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="x86_64"
OUTDIR="${CURRENT_PATH}/output"
REVISION="1"
BUILD_DOCKER="yes"
RPM_X86_BUILDER="rpm_builder_x86"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/docker"
INSTALLATION_PATH="/var/wazuh-indexer"

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.gz,wazuh-*}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

build_rpm() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    # Copy the necessary files
    cp ${CURRENT_PATH}/builder.sh ${DOCKERFILE_PATH}

    ${DOWNLOAD_TAR}

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
      docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the RPM package with a Docker container
    docker run -t --rm -v ${OUTDIR}/:/tmp:Z \
        -v ${CURRENT_PATH}/wazuh-indexer.spec:/root/wazuh-indexer.spec \
        ${CONTAINER_NAME} ${ARCHITECTURE} \
        ${REVISION} ${INSTALLATION_PATH} || return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {
    BUILD_NAME=""
    FILE_PATH=""
    if [[ "${ARCHITECTURE}" == "x86_64" ]] || [[ ${ARCHITECTURE} == "amd64" ]]; then
        ARCHITECTURE="x86_64"
        BUILD_NAME="${RPM_X86_BUILDER}"
        FILE_PATH="${RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    else
        echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too)"
        return 1
    fi
    build_rpm ${BUILD_NAME} ${FILE_PATH} || return 1

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [x86_64]."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /usr/share/wazuh-indexer"
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    -h, --help                 Show this help."
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
        "-a"|"--architecture")
            if [ -n "$2" ]; then
                ARCHITECTURE="$2"
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
        "-p"|"--path")
            if [ -n "$2" ]; then
                INSTALLATION_PATH="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--dont-build-docker")
            BUILD_DOCKER="no"
            shift 1
            ;;
        "-s"|"--store")
            if [ -n "$2" ]; then
                OUTDIR="$2"
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