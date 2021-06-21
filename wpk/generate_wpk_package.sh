#!/bin/bash

# Program to build the Wazuh WPK packages
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname ${0}) ; pwd -P )"
LINUX_BUILDER_X86_64="linux_wpk_builder_x86_64"
LINUX_BUILDER_X86_64_DOCKERFILE="${CURRENT_PATH}/linux/x86_64"
LINUX_BUILDER_AARCH64="linux_wpk_builder_aarch64"
LINUX_BUILDER_AARCH64_DOCKERFILE="${CURRENT_PATH}/linux/aarch64"
LINUX_BUILDER_ARMV7HL="linux_wpk_builder_armv7hl"
LINUX_BUILDER_ARMV7HL_DOCKERFILE="${CURRENT_PATH}/linux/armv7hl"
WIN_BUILDER="windows_wpk_builder"
WIN_BUILDER_DOCKERFILE="${CURRENT_PATH}/windows"

LINUX_BUILDER="${LINUX_BUILDER_X86_64}"
LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_X86_64_DOCKERFILE}"

BRANCH="v4.2.0-rc7"
TARGET=""
ARCHITECTURE="x86_64"
JOBS="4"
CONTAINER_NAME=""
PKG_NAME=""
NO_COMPILE=false
CHECKSUMDIR=""
WPK_KEY=""
WPK_CERT=""
AWS_REGION="us-east-1"
CHECKSUM="no"
INSTALLATION_PATH="/var/ossec"
DESTINATION="${CURRENT_PATH}/output/"
VOLUME_PKG=""

HAVE_TARGET=false
HAVE_KEYDIR=false
HAVE_PKG_NAME=false
HAVE_OUT_NAME=false
HAVE_WPK_KEY=false
HAVE_WPK_CERT=false

trap ctrl_c INT

function build_wpk() {

    if [ -n "${CHECKSUM}" ]; then
        CHECKSUM_FLAG="-c"
    fi
    if [ -n "${WPK_KEY}" ]; then
        WPK_KEY_FLAG="--aws-wpk-key ${WPK_KEY}"
    fi
    if [ -n "${WPK_CERT}" ]; then
        WPK_CERT_FLAG="--aws-wpk-cert ${WPK_CERT}"
    fi

    if [[ "${TARGET}" == "windows" ]]; then
        VOLUME_PKG="-v ${PKG_PATH}:/var/pkg:Z"
        PKG_NAME_DOCKER="-pn ${PKG_NAME}"
    fi
    
    docker run -t --rm -v ${KEYDIR}:/etc/wazuh:Z -v ${DESTINATION}:/var/local/wazuh:Z ${VOLUME_PKG} \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        ${CONTAINER_NAME} -b ${BRANCH} -j ${JOBS} -o ${OUT_NAME} -p ${INSTALLATION_PATH} --aws-wpk-key-region ${AWS_REGION} ${WPK_KEY_FLAG} ${WPK_CERT_FLAG} ${PKG_NAME_DOCKER} ${CHECKSUM_FLAG}

    return $?
}

function build_container() {
    CONTAINER_NAME="${1}"
    DOCKERFILE_PATH="${2}"

    cp run.sh wpkpack.py ${DOCKERFILE_PATH}
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}
}


function help() {
    echo
    echo "Usage: ${0} [OPTIONS]"
    echo "*It is required to use -k or [--aws-wpk-key, --aws-wpk-cert] parameters"
    echo
    echo "    -t,   --target-system <target> [Required] Select target wpk to build [linux/windows]"
    echo "    -pn,  --package-name <name>    [Required for windows] Package name to pack on wpk."
    echo "    -b,   --branch <branch>        [Optional] Select Git branch or tag. By default: ${BRANCH}"
    echo "    -d,   --destination <path>     [Optional] Set the destination path of package. By default a output folder will be created."
    echo "    -o,   --output <name>          [Optional] Name to the output package."
    echo "    -k,   --key-dir <path>         [Required*] Set the WPK key path to sign package."
    echo "    --aws-wpk-key                  [Required*] AWS Secrets manager Name/ARN to get WPK private key."
    echo "    --aws-wpk-cert                 [Required*] AWS secrets manager Name/ARN to get WPK certificate."
    echo "    --aws-wpk-key-region           [Optional] AWS Region where secrets are stored."
    echo "    -a,   --architecture <arch>    [Optional] Target architecture of the package [x86_64/aarch64/armv7hl]. By default: ${ARCHITECTURE}"
    echo "    -j,   --jobs <number>          [Optional] Number of parallel jobs when compiling."
    echo "    -p,   --path <path>            [Optional] Installation path for the package. By default: ${INSTALLATION_PATH}"
    echo "    -c,   --checksum <path>        [Optional] Generate checksum on the desired path."
    echo "    -h,   --help                   Show this help."
    echo
    exit ${1}
}


function clean() {
    DOCKERFILE_PATH="${1}"
    exit_code="${2}"

    rm -f ${DOCKERFILE_PATH}/*.sh ${DOCKERFILE_PATH}/wpkpack.py
    exit ${exit_code}
}


ctrl_c() {
    clean 1
}


function main() {


    while [ -n "${1}" ]
    do
        case "${1}" in
        "-t"|"--target-system")
            if [ -n "${2}" ]; then
                if [[ "${2}" == "linux" || "${2}" == "windows" ]]; then
                    TARGET="${2}"
                    HAVE_TARGET=true
                    shift 2
                else
                    echo "Target system must be linux or windows"
                    help 1
                fi
            else
                echo "ERROR: Missing target system."
                help 1
            fi
            ;;
        "-b"|"--branch")
            if [ -n "${2}" ]; then
                BRANCH="$2"
                shift 2
            else
                echo "ERROR: Missing branch."
                help 1
            fi
            ;;
        "-d"|"--destination")
            if [ -n "${2}" ]; then
                DESTINATION="${2}"
                shift 2
            else
                echo "ERROR: Missing destination directory."
                help 1
            fi
            ;;
        "-k"|"--key-dir")
            if [ -n "${2}" ]; then
                if [[ "${2: -1}" != "/" ]]; then
                    KEYDIR="${2}/"
                    HAVE_KEYDIR=true
                else
                    KEYDIR="${2}"
                    HAVE_KEYDIR=true
                fi
                shift 2
            fi
            ;;
        "-a"|"--architecture")
            if [ -n "${2}" ]; then
                if [[ "${2}" == "x86_64" ]] || [[ "${2}" == "amd64" ]]; then
                    ARCHITECTURE="x86_64"
                    LINUX_BUILDER="${LINUX_BUILDER_X86_64}"
                    LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_X86_64_DOCKERFILE}"
                    shift 2
                elif [[ "${2}" == "aarch64" ]]; then
                    ARCHITECTURE="${2}"
                    LINUX_BUILDER="${LINUX_BUILDER_AARCH64}"
                    LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_AARCH64_DOCKERFILE}"
                    shift 2
                elif [[ "${2}" == "armv7hl" ]]; then
                    ARCHITECTURE="${2}"
                    LINUX_BUILDER="${LINUX_BUILDER_ARMV7HL}"
                    LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_ARMV7HL_DOCKERFILE}"
                    shift 2
                else
                    echo "Architecture must be x86_64/amd64, aarch64 or armv7hl"
                    help 1
                fi
            else
              echo "ERROR: Missing architecture."
              help 1
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "${2}" ]; then
                JOBS="${2}"
                shift 2
            else
                echo "ERROR: Missing jobs."
                help 1
            fi
            ;;
        "-p"|"--path")
              if [ -n "${2}" ]; then
                  INSTALLATION_PATH="${2}"
                  shift 2
              else
                  help 1
              fi
              ;;
        "-pn"|"--package-name")
            if [ -n "${2}" ]; then
                HAVE_PKG_NAME=true
                PKG="${2}"
                PKG_NAME=$(basename ${PKG})
                PKG_PATH=$(dirname ${PKG})
            
                if [ "${PKG:0:1}" != "/" ]; then
                   PKG_PATH="$(pwd)/${PKG_PATH}"
                fi

                shift 2
            else
                echo "ERROR: Missing package name"
                help 1
            fi
            ;;
        "-o"|"--output")
            if [ -n "${2}" ]; then
                HAVE_OUT_NAME=true
                OUT_NAME="${2}"
                shift 2
            else
                echo "ERROR: Missing output name."
                help 1
            fi
            ;;
        "--aws-wpk-key")
            if [ -n "${2}" ]; then
                HAVE_WPK_KEY=true
                WPK_KEY="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-cert")
            if [ -n "${2}" ]; then
                HAVE_WPK_CERT=true
                WPK_CERT="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-key-region")
            if [ -n "${2}" ]; then
                AWS_REGION="${2}"
                shift 2
            fi
            ;;
        "-c"|"--checksum")
            if [ -n "${2}" ]; then
                CHECKSUMDIR="${2}"
                CHECKSUM="yes"
                shift 2
            else
                CHECKSUM="no"
                shift 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        *)
            help 1
        esac
    done

    if [[ "${HAVE_KEYDIR}" == false && ("${HAVE_WPK_KEY}" == false || "${HAVE_WPK_CERT}" == false) ]]; then
        echo "ERROR: Option -k or -wk, -wc must be set."
        help 1
    fi

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${DESTINATION}"
    fi

    if [[ "${HAVE_TARGET}" == true ]]; then

        if [[ "${HAVE_OUT_NAME}" == false ]]; then
            [[ "${TARGET}" == "windows" ]] && OUT_NAME="WindowsAgent.wpk" || OUT_NAME="LinuxAgent.wpk"
        fi

        if [[ "${TARGET}" == "windows" ]] && [[ "${HAVE_PKG_NAME}" == false ]]; then
            echo "To build a windows packages is needed a msi file."
            help 1
        fi

        if [[ "${TARGET}" == "linux" ]]; then
            BUILDER=${LINUX_BUILDER}
            BUILDER_DOCKERFILE=${LINUX_BUILDER_DOCKERFILE}
            PKG_NAME="N/A"
        elif [[ "${TARGET}" == "windows" ]]; then
            BUILDER=${WIN_BUILDER}
            BUILDER_DOCKERFILE=${WIN_BUILDER_DOCKERFILE}
        fi

        build_container ${BUILDER} ${BUILDER_DOCKERFILE} || clean ${BUILDER_DOCKERFILE} 1
        build_wpk ${TARGET} ${BRANCH} ${DESTINATION} ${BUILDER} ${JOBS} ${PKG_NAME} ${OUT_NAME} ${CHECKSUM} ${CHECKSUMDIR} ${INSTALLATION_PATH} ${AWS_REGION} ${WPK_KEY} ${WPK_CERT} || clean ${BUILDER_DOCKERFILE} 1
        clean ${BUILDER_DOCKERFILE} 0

    else
        echo "ERROR: Need more parameters"
        help 1
    fi

    return 0
}

main "$@"
