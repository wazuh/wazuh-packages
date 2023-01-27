#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
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
BUILD_DOCKER="yes"
DOCKER_TAG="latest"
INSTALLATION_PATH="/var/ossec"
DEB_AMD64_BUILDER="deb_builder_amd64"
DEB_I386_BUILDER="deb_builder_i386"
DEB_PPC64LE_BUILDER="deb_builder_ppc64le"
DEB_ARM64_BUILDER="deb_builder_arm64"
DEB_ARMHF_BUILDER="deb_builder_armhf"
DEB_AMD64_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/amd64"
DEB_I386_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/i386"
DEB_PPC64LE_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/ppc64le"
DEB_ARM64_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/arm64"
DEB_ARMHF_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/armhf"
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

build_deb() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    # Copy the necessary files
    cp ${CURRENT_PATH}/build.sh ${DOCKERFILE_PATH}

    # Create an optional parameter to share the local source code as a volume
    if [ ! -z "${LOCAL_SOURCE_CODE}" ]; then
        CUSTOM_CODE_VOL="-v ${LOCAL_SOURCE_CODE}:/wazuh-local-src:Z"
        USE_LOCAL_SOURCE_CODE="yes"
    fi

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${CONTAINER_NAME}:${DOCKER_TAG} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the Debian package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        -v ${LOCAL_SPECS}:/specs:Z \
        ${CUSTOM_CODE_VOL} \
        ${CONTAINER_NAME}:${DOCKER_TAG} ${TARGET} ${BRANCH} ${ARCHITECTURE} \
        ${REVISION} ${JOBS} ${INSTALLATION_PATH} ${DEBUG} \
        ${CHECKSUM} ${PACKAGES_BRANCH} ${USE_LOCAL_SPECS} \
        ${USE_LOCAL_SOURCE_CODE} ${FUTURE}|| return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {

    if [[ "${ARCHITECTURE}" = "x86_64" ]] || [[ "${ARCHITECTURE}" = "amd64" ]]; then
            ARCHITECTURE="amd64"
    elif [[ "${ARCHITECTURE}" = "aarch64" ]] || [[ "${ARCHITECTURE}" = "arm64" ]]; then
            ARCHITECTURE="arm64"
    elif [[ ${ARCHITECTURE} == "arm32" ]] || [[ ${ARCHITECTURE} == "armhf" ]] || [[ ${ARCHITECTURE} == "armv7hl" ]] ; then
        ARCHITECTURE="armhf"
    fi

    if [[ "${TARGET}" == "api" ]]; then

        if [[ "${ARCHITECTURE}" = "ppc64le" ]]; then
            build_deb ${DEB_PPC64LE_BUILDER} ${DEB_PPC64LE_BUILDER_DOCKERFILE} || return 1
        elif [[ "${ARCHITECTURE}" = "arm64" ]]; then
            build_deb ${DEB_ARM64_BUILDER} ${DEB_ARM64_BUILDER_DOCKERFILE} || return 1
        elif [[ "${ARCHITECTURE}" = "armhf" ]]; then
            build_deb ${DEB_ARMHF_BUILDER} ${DEB_ARMHF_BUILDER_DOCKERFILE} || return 1
        else
            build_deb ${DEB_AMD64_BUILDER} ${DEB_AMD64_BUILDER_DOCKERFILE} || return 1
        fi

    elif [[ "${TARGET}" == "manager" ]] || [[ "${TARGET}" == "agent" ]] ; then

        BUILD_NAME=""
        FILE_PATH=""
        if [[ "${ARCHITECTURE}" = "amd64" ]]; then
            BUILD_NAME="${DEB_AMD64_BUILDER}"
            FILE_PATH="${DEB_AMD64_BUILDER_DOCKERFILE}"
        elif [[ "${ARCHITECTURE}" = "i386" ]]; then
            BUILD_NAME="${DEB_I386_BUILDER}"
            FILE_PATH="${DEB_I386_BUILDER_DOCKERFILE}"
        elif [[ "${ARCHITECTURE}" = "ppc64le" ]]; then
            BUILD_NAME="${DEB_PPC64LE_BUILDER}"
            FILE_PATH="${DEB_PPC64LE_BUILDER_DOCKERFILE}"
        elif [[ "${ARCHITECTURE}" = "arm64" ]]; then
            BUILD_NAME="${DEB_ARM64_BUILDER}"
            FILE_PATH="${DEB_ARM64_BUILDER_DOCKERFILE}"
        elif [[ "${ARCHITECTURE}" = "armhf" ]]; then
            BUILD_NAME="${DEB_ARMHF_BUILDER}"
            FILE_PATH="${DEB_ARMHF_BUILDER_DOCKERFILE}"
        else
            echo "Invalid architecture. Choose one of amd64/i386/ppc64le/arm64/arm32."
            return 1
        fi
        build_deb ${BUILD_NAME} ${FILE_PATH} || return 1
    else
        echo "Invalid target. Choose: manager or agent."
        return 1
    fi

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>      [Required] Select Git branch [${BRANCH}]. By default: master."
    echo "    -t, --target <target>      [Required] Target package to build: manager or agent."
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64/i386/ppc64le/arm64/armhf]."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug                [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum <path>      [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --tag                      [Optional] Tag to use with the docker image."
    echo "    --sources <path>           [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo "    --packages-branch <branch> [Optional] Select Git branch or tag from wazuh-packages repository. e.g master."
    echo "    --dev                      [Optional] Use the SPECS files stored in the host instead of downloading them from GitHub."
    echo "    --future                   [Optional] Build test future package x.30.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
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
        "--dont-build-docker")
            BUILD_DOCKER="no"
            shift 1
            ;;
        "--tag")
            if [ -n "$2" ]; then
                DOCKER_TAG="$2"
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
