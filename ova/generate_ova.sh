#!/bin/sh

# Program to build the Wazuh Virtual Machine
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
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
HAVE_VERSION=false
HAVE_OPENDISTRO_VERSION=false
HAVE_ELK_VERSION=false

WAZUH_VERSION=""
OPENDISTRO_VERSION=""
BRANCH="2205-Open_Distro_installation"
ELK_VERSION=""
STATUS=""
CHECKSUM="no"

help () {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo "  -v, --version          [Required] Version of wazuh to install on VM."
    echo "  -o, --opendistro       [Required] Version of Open Distro for Elasticsearch."
    echo "  -f, --filebeat         [Required] Filebeat version to download inside VM."
    echo "  -r, --repository       [Required] Select the software repository [prod/dev]."
    echo "  -b, --branch           [Optional] Branch/tag of the Wazuh repository."
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
    export BRANCH

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

    vagrant destroy -f
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
    if [ "${STATUS}" = "prod" ]; then
        WAZUH_MAJOR="$(echo ${WAZUH_VERSION} | head -c 1)"
        curl -Isf https://packages.wazuh.com/${WAZUH_MAJOR}/ui/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
    elif [ "${STATUS}" = "dev" ]; then
        curl -Isf https://packages-dev.wazuh.com/pre-release/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-1.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
    else
        logger "Error, repository value must take 'prod' or 'dev' value."
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

        "-v" | "--version")
            if [ -n "$2" ]; then

                export WAZUH_VERSION="$2"
                HAVE_VERSION=true
            else
                logger "ERROR Need wazuh version."
                help 1
            fi
            shift 2
        ;;
        "-o" | "--opendistro")
            if [ -n "$2" ]; then

                export OPENDISTRO_VERSION="$2"
                HAVE_OPENDISTRO_VERSION=true
            else
                logger "ERROR Need opendistro version."
                help 1
            fi
            shift 2
        ;;

        "-f" | "--filebeat")
            if [ -n "$2" ]; then

                export ELK_VERSION="$2"
                HAVE_ELK_VERSION=true
            else
                logger "ERROR: Need filebeat version."
                help 1
            fi
            shift 2
        ;;

        "-r" | "--repository")
            if [ -n "$2" ]; then

                export STATUS="$2"
                HAVE_STATUS=true
            else
                logger "ERROR: package repository is needed."
                help 1
            fi
            shift 2
        ;;
        "-b"|"--branch")
            if [ -n "$2" ]; then
            
                BRANCH="$2"
                shift 2
            else
                logger "ERROR: Need branch to build."
                help 1
            fi
            ;;
        "-s"|"--store-path")
            if [ -n "$2" ]; then
                OUTPUT_DIR="$2"
                shift 2
            else
                logger "ERROR: Need store path"
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
    if  [ "${HAVE_VERSION}" = true ] && [ "${HAVE_ELK_VERSION}" = true ] && [ "${HAVE_STATUS}" = true ] && [ "${HAVE_OPENDISTRO_VERSION}" = true ]; then
        check_version ${WAZUH_VERSION} ${ELK_VERSION} ${STATUS}
        OVA_VERSION="${WAZUH_VERSION}_${OPENDISTRO_VERSION}"

        logger "Version to build: ${WAZUH_VERSION}-${OPENDISTRO_VERSION} with ${STATUS} repository and ${BRANCH} branch"
        build_ova ${WAZUH_VERSION} ${OVA_VERSION}
    else
        logger "ERROR: Need more parameters."
        help 1
    fi

    return 0
}

main "$@"
