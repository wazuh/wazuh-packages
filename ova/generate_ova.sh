#!/bin/sh

# Program to build the Wazuh Virtual Machine
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
set -e
# Dependencies: vagrant, virtualbox, ovftool

#
# CONFIGURATION VARIABLES

scriptpath=$(
    cd $(dirname $0)
    pwd -P
)

OUTPUT_DIR="${scriptpath}/output"
CHECKSUM_DIR=""
BUILD=false
HAVE_VERSION=false
HAVE_ELK_VERSION=false

WAZUH_VERSION=""
ELK_VERSION=""
STATUS=""
CHECKSUM="no"

help () {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "  -b, --build            [Required] Build the OVA and OVF."
    echo "  -v, --version          [Required] Version of wazuh to install on VM."
    echo "  -e, --elastic-version  [Required] Elastic version to download inside VM."
    echo "  -r, --repository       [Required] Status of the packages [stable/unstable]"
    echo "  -d, --directory        [Optional] Where will be installed manager. Default /var/ossec"
    echo "  -s, --store <path>     [Optional] Set the destination absolute path of package."
    echo "  -c, --checksum <path>  [Optional] Generate checksum."
    echo "  -h, --help             [  Util  ] Show this help."
    echo
    exit $1
}

clean() {
    exit_code=$1

    cd ${scriptpath}
    vagrant destroy -f
    rm -f ${OVA_VM} ${OVF_VM} ${OVA_VMDK} ${OVA_FIXED} Config_files/filebeat.yml

    exit ${exit_code}
}

build_ova() {

    OVA_VM="wazuh${OVA_VERSION}.ova"
    OVF_VM="wazuh${OVA_VERSION}.ovf"
    OVA_FIXED="wazuh${OVA_VERSION}-fixed.ova"
    OVA_VMDK="wazuh${OVA_VERSION}-disk001.vmdk"
    ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`

    if [ -e "${OVA_VM}" ] || [ -e "${OVA_VM}" ]; then
        rm -f ${OVA_VM} ${OVF_VM}
    fi

    #Download filebeat.yml and enable geoip
    if [ ${ELK_MAJOR} -eq 7 ]; then
        curl -so Config_files/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}/extensions/filebeat/7.x/filebeat.yml
        sed -i "s|#pipeline: geoip|pipeline: geoip|" Config_files/filebeat.yml
    fi


    # Vagrant will provision the VM with all the software. (See vagrant file)
    vagrant destroy -f
    vagrant up || clean 1
    vagrant suspend
    VM_EXPORT=$(vboxmanage list vms | grep -i vm_wazuh | cut -d "\"" -f2)
    # OVA creation with all metadata information.
    vboxmanage export ${VM_EXPORT} -o ${OVA_VM} --vsys 0 --product "Wazuh v${WAZUH_VERSION} OVA" --producturl "https://packages.wazuh.com/vm/wazuh${OVA_VERSION}.ova" --vendor "Wazuh, inc <info@wazuh.com>" --vendorurl "https://wazuh.com" --version "$OVA_VERSION" --description "Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring." || clean 1

    tar -xvf ${OVA_VM}

    python Ova2Ovf.py -s ${OVA_VM} -d ${OVA_FIXED}

    mkdir -p ${OUTPUT_DIR}
    mv ${OVA_FIXED} ${OUTPUT_DIR}/${OVA_VM}

    if [ "${CHECKSUM}" = "yes" ]; then
        mkdir -p ${CHECKSUM_DIR}
        cd ${OUTPUT_DIR} && sha512sum "${OVA_VM}" > "${CHECKSUM_DIR}/${OVA_VM}.sha512"
    fi

    # Cleaning tasks
    clean 0
    }

    check_version() {

    if [ "${STATUS_PACKAGES}" = "stable" ]; then
        curl -Isf https://raw.githubusercontent.com/wazuh/wazuh-kibana-app/v${WAZUH_VERSION}-${ELK_VERSION}/README.md > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
    elif [ "${STATUS_PACKAGES}" = "unstable" ]; then
        curl -Isf https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
    else
        echo "Error, repository value must take 'stable' or 'unstable' value."
        exit
    fi
}

main() {

    export DIRECTORY="/var/ossec"
    while [ -n "$1" ]; do
        case $1 in
            "-h" | "--help")
            help 0
        ;;

        "-b" | "--build")
            BUILD=true
            shift 1
        ;;

        "-v" | "--version")
            if [ -n "$2" ]; then
                export OVA_WAZUH_VERSION="$2"
                WAZUH_VERSION="$2"
                HAVE_VERSION=true
            else
                echo "ERROR Need wazuh version."
                help 1
            fi
            shift 2
        ;;

        "-e" | "--elastic-version")
            if [ -n "$2" ]; then
                export OVA_ELK_VERSION="$2"
                ELK_VERSION="$2"
                HAVE_ELK_VERSION=true
            else
                echo "ERROR: Need elastic version."
                help 1
            fi
            shift 2
        ;;

        "-r" | "--repository")
            if [ -n "$2" ]; then
                export STATUS_PACKAGES="$2"
                STATUS="$2"
                HAVE_STATUS=true
            else
                echo "ERROR: package repository is needed_."
                help 1
            fi
            shift 2
        ;;

        "-d" | "--directory")
            if [ -n "$2" ]; then
                export DIRECTORY="$2"
            else
                echo "ERROR: Need directory to build."
                help 1
            fi
            shift 2
        ;;

        "-s"|"--store-path")
            if [ -n "$2" ]; then
                OUTPUT_DIR="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-c"|"--checksum")
            if [ -n "$2" ]; then
                CHECKSUM_DIR="$2"
                CHECKSUM="yes"
                shift 2
            else
                CHECKSUM="yes"
                shift 1
            fi
        ;;
        *)
            help 1
        ;;
        esac
    done

    if [ -z "${CHECKSUM_DIR}" ]; then
        CHECKSUM_DIR="${OUTPUT_DIR}"
    fi

    if [ "${BUILD}" = true ] && [ "${HAVE_VERSION}" = true ] && [ "${HAVE_ELK_VERSION}" = true ] && [ "${HAVE_STATUS}" = true ]; then
        check_version ${WAZUH_VERSION} ${ELK_VERSION} ${STATUS}
        OVA_VERSION="${WAZUH_VERSION}_${ELK_VERSION}"

        echo "Version to build: ${WAZUH_VERSION}-${ELK_VERSION} with ${STATUS} repository."
        build_ova ${WAZUH_VERSION} ${OVA_VERSION}
    else
        echo "ERROR: Need more parameters."
        help 1
    fi

    return 0
}

main "$@"
