#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="amd64"
OUTDIR="${CURRENT_PATH}/output/"
BRANCH=""
REVISION="1"
TARGET=""
JOBS="2"
DEBUG="no"
INSTALLATION_PATH="/var/ossec"
DEB_AMD64_BUILDER="deb_builder_amd64"
DEB_I386_BUILDER="deb_builder_i386"
DEB_PPC64LE_BUILDER="deb_builder_ppc64le"
DEB_AMD64_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/amd64"
DEB_I386_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/i386"
CHECKSUMDIR=""
CHECKSUM="no"
DEB_PPC64LE_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/ppc64le"
PACKAGES_BRANCH="master"
USE_LOCAL_SPECS="no"
LOCAL_SPECS="${CURRENT_PATH}"

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

build_deb() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1

    # Build the Debian package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        -v ${LOCAL_SPECS}:/specs:Z \
        ${CONTAINER_NAME} ${TARGET} ${BRANCH} ${ARCHITECTURE} \
        ${REVISION} ${JOBS} ${INSTALLATION_PATH} ${DEBUG} \
        ${CHECKSUM} ${PACKAGES_BRANCH} ${USE_LOCAL_SPECS} || return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {

    if [[ "${TARGET}" == "api" ]]; then

        if [[ "${ARCHITECTURE}" = "ppc64le" ]]; then
            build_deb ${DEB_PPC64LE_BUILDER} ${DEB_PPC64LE_BUILDER_DOCKERFILE} || return 1
        else
            build_deb ${DEB_AMD64_BUILDER} ${DEB_AMD64_BUILDER_DOCKERFILE} || return 1
        fi

    elif [[ "${TARGET}" == "manager" ]] || [[ "${TARGET}" == "agent" ]]; then

        BUILD_NAME=""
        FILE_PATH=""
        if [[ "${ARCHITECTURE}" = "x86_64" ]] || [[ "${ARCHITECTURE}" = "amd64" ]]; then
            ARCHITECTURE="amd64"
            BUILD_NAME="${DEB_AMD64_BUILDER}"
            FILE_PATH="${DEB_AMD64_BUILDER_DOCKERFILE}"
        elif [[ "${ARCHITECTURE}" = "i386" ]]; then
            BUILD_NAME="${DEB_I386_BUILDER}"
            FILE_PATH="${DEB_I386_BUILDER_DOCKERFILE}"
        elif [[  "${ARCHITECTURE}" = "ppc64le" ]]; then
            BUILD_NAME="${DEB_PPC64LE_BUILDER}"
            FILE_PATH="${DEB_PPC64LE_BUILDER_DOCKERFILE}"
        else
            echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too) or i386 or ppc64le."
            return 1
        fi
        build_deb ${BUILD_NAME} ${FILE_PATH} || return 1
    else
        echo "Invalid target. Choose: manager, agent or api."
        return 1
    fi

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch [${BRANCH}]. By default: master."
    echo "    -t, --target <target>     [Required] Target package to build: manager, api or agent."
    echo "    -a, --architecture <arch> [Optional] Target architecture of the package. By default: x86_64"
    echo "    -j, --jobs <number>       [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 4."
    echo "    -r, --revision <rev>      [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>        [Optional] Set the directory where the package will be stored. By default: ${HOME}/3.x/apt-dev/"
    echo "    -p, --path <path>         [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug               [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum <path>     [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    --dev                     [Optional] Use the SPECS files stored in the host instead of downloading them from GitHub."
    echo "    -h, --help                Show this help."
    echo
    exit $1
}


main() {
    BUILD="no"
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
        "-t"|"--target")
            if [ -n "$2" ]; then
                TARGET="$2"
                shift 2
            else
                help 1
            fi
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
                shift 2
            fi
            ;;
        "--dev")
            USE_LOCAL_SPECS="yes"
            shift 1
            ;;
        *)
            help 1
        esac
    done

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
