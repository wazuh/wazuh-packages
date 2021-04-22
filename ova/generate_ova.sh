#!/bin/sh

# Program to build the Wazuh Virtual Machine
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Use example ./generate_ova.sh -p 4.1 -v 4.1.4 -o 1.12.0 -f 7.10.0 -r dev -b wj-2421-ova-rework 


set -e
# Dependencies: vagrant, virtualbox, ovftool


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
HAVE_PACKAGE_VERSION=false

INSTALLER="all-in-one-installation.sh"
export INSTALLER

PACKAGE_VERSION=""
WAZUH_VERSION=""
OPENDISTRO_VERSION=""
BRANCH="master"
ELK_VERSION=""
PACKAGES_REPOSITORY=""
CHECKSUM="no"
UI_REVISION="1"

help () {

    echo
    echo "Usage: $0 [OPTIONS]"
    echo "  -p, --package          [Required] Select Git branch or tag from wazuh-packages repository."
    echo "  -v, --version          [Required] Version of wazuh to install on VM."
    echo "  -o, --opendistro       [Required] Version of Open Distro for Elasticsearch."
    echo "  -f, --filebeat         [Required] Filebeat's version."
    echo "  -r, --repository       [Required] Select the software repository [prod/dev]."
    echo "  -b, --branch           [Optional] Branch/tag of the Wazuh repository."
    echo "  -s, --store <path>     [Optional] Set the destination absolute path of package."
    echo "  -c, --checksum <path>  [Optional] Generate checksum."
    echo "  -u, --ui-revision      [Optional] Revision of the UI package. By default, 1."
    echo "  -h, --help             [  Util  ] Show this help."
    echo
    exit $1
}

clean() {
    exit_code=$1

    cd ${scriptpath}
    vagrant destroy -f
    rm -f ${OVA_VM} ${OVF_VM} ${OVA_VMDK} ${OVA_FIXED}
    
    exit ${exit_code}
}

build_ova() {

    OVA_VM="wazuh-${OVA_VERSION}.ova"
    OVF_VM="wazuh-${OVA_VERSION}.ovf"
    OVA_FIXED="wazuh-${OVA_VERSION}-fixed.ova"
    OVA_VMDK="wazuh-${OVA_VERSION}-disk001.vmdk"
    export BRANCH

    # Delete OVA/OVF files if exists
    if [ -e "${OUTPUT_DIR}/${OVA_VM}" ] || [ -e "${OUTPUT_DIR}/${OVF_VM}" ]; then
        rm -f ${OUTPUT_DIR}/${OVA_VM} ${OUTPUT_DIR}/${OVF_VM}
    fi

    # Download unattended installer
    curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${PACKAGE_VERSION}/resources/open-distro/unattended-installation/${INSTALLER} 

    # Get currents version values of installer
    ACTUAL_W=$(less ${INSTALLER} | grep "WAZUH_VER=")
    ACTUAL_O=$(less ${INSTALLER} | grep "OD_VER=")
    ACTUAL_E=$(less ${INSTALLER} | grep "ELK_VER=")

    # Change specified versions in unattended installer
    sed -i "s/${ACTUAL_W}/WAZUH_VER=\"${WAZUH_VERSION}\"/g" ${INSTALLER}
    sed -i "s/${ACTUAL_O}/OD_VER=\"${OPENDISTRO_VERSION}\"/g" ${INSTALLER}
    sed -i "s/${ACTUAL_E}/ELK_VER=\"${ELK_VERSION}\"/g" ${INSTALLER}

    # Vagrant will provision the VM with all the software. (See vagrant file)
    vagrant destroy -f
    vagrant up
    vagrant suspend

    # OVA creation with all metadata information.
    VM_EXPORT=$(vboxmanage list vms | grep -i vm_wazuh | cut -d "\"" -f2)
    vboxmanage export ${VM_EXPORT} -o ${OVA_VM} --vsys 0 --product "Wazuh v${WAZUH_VERSION} OVA" --producturl "https://packages.wazuh.com/vm/wazuh-${OVA_VERSION}.ova" --vendor "Wazuh, inc <info@wazuh.com>" --vendorurl "https://wazuh.com" --version "$OVA_VERSION" --description "Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring." || clean 1

    # Destroy vagrant machine
    vagrant destroy -f

    # Create file
    tar -xvf ${OVA_VM}

    # Configure OVA file (SATA, sound, etc)
    python Ova2Ovf.py -s ${OVA_VM} -d ${OVA_FIXED}

    # Make output dir of OVA file
    mkdir -p ${OUTPUT_DIR}
    mv ${OVA_FIXED} ${OUTPUT_DIR}/${OVA_VM}

    # Check Checksum
    if [ "${CHECKSUM}" = "yes" ]; then
        mkdir -p ${CHECKSUM_DIR}
        cd ${OUTPUT_DIR} && sha512sum "${OVA_VM}" > "${CHECKSUM_DIR}/${OVA_VM}.sha512"
    fi

    # Remove installer file
    rm ${INSTALLER}

}

check_version() {
    if [ "${PACKAGES_REPOSITORY}" = "prod" ]; then
        WAZUH_MAJOR="$(echo ${WAZUH_VERSION} | head -c 1)"
        if [ "${WAZUH_MAJOR}" = "3" ]; then
            curl -Isf https://packages.wazuh.com/${WAZUH_MAJOR}/ui/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
        else
            curl -Isf https://packages.wazuh.com/${WAZUH_MAJOR}/ui/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}-${UI_REVISION}.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION}-${UI_REVISION} not supported." && exit 1 )
        fi
    elif [ "${PACKAGES_REPOSITORY}" = "dev" ]; then
        curl -Isf https://packages-dev.wazuh.com/pre-release/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-${UI_REVISION}.zip > /dev/null || ( echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported." && exit 1 )
    else
        logger "Error, repository value must take 'prod' or 'dev' value."
        echo "Error, repository value must take 'prod' or 'dev' value."
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
                echo "ERROR Need wazuh version."
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
                echo "ERROR Need opendistro version."
                help 1
            fi
            shift 2
        ;;

        "-p" | "--package")
            if [ -n "$2" ]; then
                export PACKAGE_VERSION="$2"
                HAVE_PACKAGE_VERSION=true
            else
                logger "ERROR Need package version (4.1, 4.2, ...)"
                echo "ERROR Need package version (4.1, 4.2, ...)"
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
                echo "ERROR: Need filebeat version."
                help 1
            fi
            shift 2
        ;;

        "-r" | "--repository")
            if [ -n "$2" ]; then
                export PACKAGES_REPOSITORY="$2"
                HAVE_PACKAGES_REPOSITORY=true
            else
                logger "ERROR: package repository is needed."
                echo "ERROR: package repository is needed."
                help 1
            fi
            shift 2
        ;;

        "-u" | "--ui")
            if [ -n "$2" ]; then
                UI_REVISION="$2"
            else
                logger "ERROR: package repository is needed."
                echo "ERROR: package repository is needed."
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
                echo "ERROR: Need branch to build."
                help 1
            fi
        ;;

        "-s"|"--store-path")
            if [ -n "$2" ]; then
                OUTPUT_DIR="$2"
                shift 2
            else
                logger "ERROR: Need store path"
                echo "ERROR: Need store path"
                help 1
            fi
        ;;

        "-c"|"--checksum")
            if [ -n "$2" ]; then
                CHECKSUM_DIR="$2"
                CHECKSUM="yes"
                shift 2
            else
                CHECKSUM="no"
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
    if  [ "${HAVE_PACKAGE_VERSION}" = true ] && [ "${HAVE_VERSION}" = true ] && [ "${HAVE_ELK_VERSION}" = true ] && [ "${HAVE_PACKAGES_REPOSITORY}" = true ] && [ "${HAVE_OPENDISTRO_VERSION}" = true ]; then
        export UI_REVISION="${UI_REVISION}"
        check_version
        OVA_VERSION="${WAZUH_VERSION}_${OPENDISTRO_VERSION}"
        logger "Version to build: ${WAZUH_VERSION}-${OPENDISTRO_VERSION} with ${PACKAGES_REPOSITORY} repository and ${BRANCH} branch of package ${PACKAGE_VERSION}"
        echo "Version to build: ${WAZUH_VERSION}-${OPENDISTRO_VERSION} with ${PACKAGES_REPOSITORY} repository and ${BRANCH} branch of package ${PACKAGE_VERSION}"
        
        # Build OVA file (no standard)
        build_ova ${WAZUH_VERSION} ${OVA_VERSION} ${PACKAGE_VERSION}

        # Standarize OVA and finish
        ./setOVADefault.sh ${WAZUH_VERSION} ${OPENDISTRO_VERSION} ${OUTPUT_DIR} 
        
        clean 0

    else
        logger "ERROR: Need more parameters."
        echo "ERROR: Need more parameters."
        help 1
    fi

    return 0
}

main "$@"
