#!/bin/bash

# Wazuh package generator
# Copyright (C) 2021, Wazuh Inc.
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
RPM_X86_BUILDER="rpm_dashboard_builder_x86"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/docker"
FUTURE="no"
BASE="s3"
BASE_PATH="${CURRENT_PATH}/../base/output"

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

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the RPM package with a Docker container
    VOLUMES="-v ${OUTDIR}/:/tmp:Z"
    if [ "${REFERENCE}" ];then
        docker run -t --rm ${VOLUMES} \
            ${CONTAINER_NAME} ${ARCHITECTURE} ${REVISION} \
            ${FUTURE} ${BASE} ${REFERENCE} || return 1
    else
        if [ "${BASE}" = "local" ];then
            VOLUMES="${VOLUMES} -v ${BASE_PATH}:/root/output:Z"
        fi
        docker run -t --rm ${VOLUMES} \
            -v ${CURRENT_PATH}/../../..:/root:Z \
            ${CONTAINER_NAME} ${ARCHITECTURE} \
            ${REVISION} ${FUTURE} ${BASE} || return 1
    fi

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {
    BUILD_NAME=""
    FILE_PATH=""
    if [ "${ARCHITECTURE}" = "x86_64" ] || [ "${ARCHITECTURE}" = "amd64" ]; then
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
    echo "    --reference <ref>          [Optional] wazuh-packages branch to download SPECs, not used by default."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --future                   [Optional] Build test future package 99.99.0 Used for development purposes."
    echo "    --base <s3/local>          [Optional] Base file location, use local or s3, default: s3"
    echo "    --base-path                [Optional] If base is local, you can indicate the full path where the base is located, default: stack/dashboard/base/output"
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
        "--reference")
            if [ -n "$2" ]; then
                REFERENCE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--dont-build-docker")
            BUILD_DOCKER="no"
            shift 1
            ;;
        "--future")
            FUTURE="yes"
            shift 1
            ;;
        "--base")
            if [ -n "$2" ]; then
                BASE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--base-path")
            if [ -n "$2" ]; then
                BASE_PATH="$2"
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
        *)
            help 1
        esac
    done

    build || clean 1

    clean 0
}

main "$@"