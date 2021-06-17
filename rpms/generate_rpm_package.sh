#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="x86_64"
OUTDIR="${CURRENT_PATH}/output/"
BRANCH=$(cat ../VERSION)
REVISION="1"
TARGET=""
JOBS="2"
DEBUG="no"
BUILD_DOCKER="yes"
USER_PATH="no"
INSTALLATION_PATH="/var/ossec"
RPM_AARCH64_BUILDER="rpm_builder_aarch64"
RPM_ARMV7HL_BUILDER="rpm_builder_armv7hl"
RPM_X86_BUILDER="rpm_builder_x86"
RPM_I386_BUILDER="rpm_builder_i386"
RPM_PPC64LE_BUILDER="rpm_builder_ppc64le"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/6"
RPM_AARCH64_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/7"
RPM_ARMV7HL_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/7"
RPM_PPC64LE_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/7"
LEGACY_RPM_X86_BUILDER="rpm_legacy_builder_x86"
LEGACY_RPM_I386_BUILDER="rpm_legacy_builder_i386"
LEGACY_RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/5"
LEGACY_TAR_FILE="${LEGACY_RPM_BUILDER_DOCKERFILE}/i386/centos-5-i386.tar.gz"
TAR_URL="https://packages-dev.wazuh.com/utils/centos-5-i386-build/centos-5-i386.tar.gz"
CHECKSUMDIR=""
CHECKSUM="no"
PACKAGES_BRANCH="master"
LOCAL_SPECS="${CURRENT_PATH}"
LOCAL_SOURCE_CODE=""
USE_LOCAL_SOURCE_CODE="no"
FUTURE="no"
SRC="no"
LEGACY="no"
HAVE_TARGET="no"

trap ctrl_c INT

if command -v curl > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="curl ${TAR_URL} -o ${LEGACY_TAR_FILE} -s"
elif command -v wget > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="wget ${TAR_URL} -o ${LEGACY_TAR_FILE} -q"
fi

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.tar.gz,wazuh*} ${DOCKERFILE_PATH}/build.sh ${SOURCES_DIRECTORY}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

build_rpm() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    # Download the legacy tar file if it is needed
    if [ "${CONTAINER_NAME}" = "${LEGACY_RPM_I386_BUILDER}" ] && [ ! -f "${LEGACY_TAR_FILE}" ]; then
        ${DOWNLOAD_TAR}
    fi

    # Create an optional parameter to share the local source code as a volume
    if [ ! -z "${LOCAL_SOURCE_CODE}" ]; then
        CUSTOM_CODE_VOL="-v ${LOCAL_SOURCE_CODE}:/wazuh-local-src:Z"
        USE_LOCAL_SOURCE_CODE="yes"
    fi

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
      docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the RPM package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        -v ${LOCAL_SPECS}:/specs:Z \
        ${CUSTOM_CODE_VOL} \
        ${CONTAINER_NAME} ${TARGET} ${BRANCH} ${ARCHITECTURE} \
        ${REVISION} ${JOBS} ${INSTALLATION_PATH} ${DEBUG} \
        ${CHECKSUM} ${PACKAGES_BRANCH} ${SRC} \
        ${LEGACY} ${USE_LOCAL_SOURCE_CODE} ${FUTURE}|| return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {

    if [[ ${ARCHITECTURE} == "amd64" ]] || [[ ${ARCHITECTURE} == "x86_64" ]]; then
        ARCHITECTURE="x86_64"
    elif [[ ${ARCHITECTURE} == "arm64" ]] || [[ ${ARCHITECTURE} == "aarch64" ]]; then
        ARCHITECTURE="aarch64"
    elif [[ ${ARCHITECTURE} == "arm32" ]] || [[ ${ARCHITECTURE} == "armhf" ]] || \
        [[ ${ARCHITECTURE} == "armhfp" ]] || [[ ${ARCHITECTURE} == "armv7hl" ]] ; then
        ARCHITECTURE="armv7hl"
    fi

    BUILD_NAME=""
    FILE_PATH=""
    if [[ "${LEGACY}" == "yes" ]] && [[ "${ARCHITECTURE}" == "x86_64" ]]; then
        REVISION="${REVISION}.el5"
        BUILD_NAME="${LEGACY_RPM_X86_BUILDER}"
        FILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "yes" ]] && [[ "${ARCHITECTURE}" == "i386" ]]; then
        REVISION="${REVISION}.el5"
        BUILD_NAME="${LEGACY_RPM_I386_BUILDER}"
        FILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "no" ]] && [[ "${ARCHITECTURE}" == "x86_64" ]]; then
        BUILD_NAME="${RPM_X86_BUILDER}"
        FILE_PATH="${RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "no" ]] && [[ "${ARCHITECTURE}" == "i386" ]]; then
        BUILD_NAME="${RPM_I386_BUILDER}"
        FILE_PATH="${RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "no" ]] && [[ "${ARCHITECTURE}" == "ppc64le" ]]; then
        BUILD_NAME="${RPM_PPC64LE_BUILDER}"
        FILE_PATH="${RPM_PPC64LE_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "no" ]] && [[ "${ARCHITECTURE}" == "aarch64" ]]; then
        BUILD_NAME="${RPM_AARCH64_BUILDER}"
        FILE_PATH="${RPM_AARCH64_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    elif [[ "${LEGACY}" == "no" ]] && [[ "${ARCHITECTURE}" == "armv7hl" ]]; then
        BUILD_NAME="${RPM_ARMV7HL_BUILDER}"
        FILE_PATH="${RPM_ARMV7HL_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
    else
        echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too), ppc64le or i386"
        return 1
    fi
    build_rpm ${BUILD_NAME} ${FILE_PATH} || return 1

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -t, --target <target>      [Required] Target package to build: manager or agent."
    echo "    -b, --branch <branch>      [Optional] Select Git branch or tag. By default: ${BRANCH}"
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [x86_64/i386/ppc64le/aarch64/armv7hl]."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 1."
    echo "    -l, --legacy               [Optional] Build package for CentOS 5. Only supported target: agent."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug                [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum <path>      [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --sources <path>           [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo "    --packages-branch <branch> [Optional] Select Git branch or tag from wazuh-packages repository. By default: ${PACKAGES_BRANCH}"
    echo "    --src                      [Optional] Generate the source package in the destination directory."
    echo "    --future                   [Optional] Build test future package x.30.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}


main() {

    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH="$2"
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
                HAVE_TARGET="yes"
                shift 2
            else
                echo "Needs a target."
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
        "-l"|"--legacy")
            LEGACY="yes"
            shift 1
            ;;
        "-d"|"--debug")
            DEBUG="yes"
            shift 1
            ;;
        "--dont-build-docker")
            BUILD_DOCKER="no"
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
                USER_PATH="yes"
                shift 2
            else
                help 1
            fi
            ;;
        "--src")
            SRC="yes"
            shift 1
            ;;
        "--packages-branch")
            if [ -n "$2" ]; then
                PACKAGES_BRANCH="$2"
                shift 2
            else
                help 1
            fi
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

    if [[ "${USER_PATH}" == "no" ]] && [[ "${LEGACY}" == "yes" ]]; then
        OUTDIR="${OUTDIR}/5/${ARCHITECTURE}"
    fi

    if [ "${HAVE_TARGET}" == "no" ]; then
        echo "Check required values"
        help 1
    fi

    if [ "${TARGET}" != "manager" ] && [ "${TARGET}" != "agent" ]; then
        echo "Target must be 'manager' or 'agent'."
        help 1
    fi

    if [ "${TARGET}" != "agent" ] && [ "${LEGACY}" = "yes" ]; then
        echo "Target ${TARGET} not supported for Centos5"
        exit $1
    fi

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${OUTDIR}"
    fi

   
    build || clean 1
    clean 0
}

main "$@"