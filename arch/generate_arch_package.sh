#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="x86_64"
OUTDIR="${CURRENT_PATH}/output/"
BRANCH=""
REVISION="1"
TARGET="agent"
JOBS="2"
DEBUG="no"
BUILD_DOCKER="yes"
INSTALLATION_PATH="/var/ossec"
ARCH_BUILDER="arch_builder"
ARCH_BUILDER_DOCKERFILE="${CURRENT_PATH}/Arch"
CHECKSUMDIR=""
CHECKSUM="no"
PACKAGES_BRANCH="master"
USE_LOCAL_SPECS="no"
LOCAL_SPECS="${CURRENT_PATH}"
LOCAL_SOURCE_CODE=""
USE_LOCAL_SOURCE_CODE="no"
FUTURE="no"

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.gz,wazuh-*} ${SOURCES_DIRECTORY}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

build_arch() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    # Create an optional parameter to share the local source code as a volume
    if [ ! -z "${LOCAL_SOURCE_CODE}" ]; then
        CUSTOM_CODE_VOL="-v ${LOCAL_SOURCE_CODE}:/wazuh-local-src:Z"
        USE_LOCAL_SOURCE_CODE="yes"
    fi

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the Arch package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        -v ${LOCAL_SPECS}:/specs:Z \
        ${CUSTOM_CODE_VOL} \
        ${CONTAINER_NAME} ${TARGET} ${BRANCH} ${ARCHITECTURE} \
        ${REVISION} ${JOBS} ${INSTALLATION_PATH} ${DEBUG} \
        ${CHECKSUM} ${PACKAGES_BRANCH} ${USE_LOCAL_SPECS} \
        ${USE_LOCAL_SOURCE_CODE} ${FUTURE}|| return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {

    if [[ "${TARGET}" == "agent" ]]; then

        build_arch ${ARCH_BUILDER} ${ARCH_BUILDER_DOCKERFILE} || return 1

    else
        echo "Invalid target. Only agent is supported."
        return 1
    fi

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>         [Required] Select Git branch [${BRANCH}]. By default: master."
    echo "    -j, --jobs <number>           [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>          [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>            [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>             [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug                   [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum <path>         [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    --dont-build-docker           [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --sources <path>              [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo "    --packages-branch <branch>    [Required] Select Git branch or tag from wazuh-packages repository. e.g ${PACKAGES_BRANCH}"
    echo "    --dev                         [Optional] Use the SPECS files stored in the host instead of downloading them from GitHub."
    echo "    --future                      [Optional] Build test future package {MAJOR}.30.0 Used for development purposes."
    echo "    -h, --help                    Show this help."
    echo
    exit $1
}


main() {
    BUILD="no"
    PBRANCH="no"
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH="$2"
                BUILD="yes"
                shift 2
            else
                help 1
            fi
            ;;
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
        "-j"|"--jobs")
            if [ -n "$2" ]; then
                JOBS="$2"
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
        "-d"|"--debug")
            DEBUG="yes"
            shift 1
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
        "--packages-branch")
            if [ -n "$2" ]; then
                PACKAGES_BRANCH="$2"
                PBRANCH="yes"
                shift 2
            else
                help 1
            fi
            ;;
        "--dev")
            USE_LOCAL_SPECS="yes"
            shift 1
            ;;
        "--sources")
            if [ -n "$2" ]; then
                LOCAL_SOURCE_CODE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--future")
            FUTURE="yes"
            shift 1
            ;;
        *)
            help 1
        esac
    done

    if [[ "${BUILD}" == "no" ]] || [[ "${PBRANCH}" == "no" ]]; then
        echo "It is required to use the (-b or --branch) and --packages-branch parameters"
        clean 1
    fi

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${OUTDIR}"
    fi

    if [[ "$BUILD" != "no" ]]; then
        build || clean 1
    else
        clean 1
    fi

    clean 0
}

main "$@"
