#!/bin/bash

# Program to build the Wazuh Virtual Machine
# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e
# Dependencies: vagrant, virtualbox

# CONFIGURATION VARIABLES

scriptpath=$(
    cd "$(dirname "$0")"
    pwd -P
)

OUTPUT_DIR="${scriptpath}/output"
CHECKSUM_DIR="${scriptpath}/checksum"

UNATTENDED_RESOURCES_FOLDER="unattended_installer"
UNATTENDED_PATH="../${UNATTENDED_RESOURCES_FOLDER}"
VERSION_FILE="../VERSION"

PACKAGES_REPOSITORY="prod"
CHECKSUM="no"
DEBUG="no"

help () {
    echo -e ""
    echo -e "NAME"
    echo -e "$(basename "$0") - Build Wazuh OVA."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") -r | -s | -c | -f | -h"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -r,  --repository"
    echo -e "                Use development or production repository."
    echo -e "                Values: [prod|dev|staging]. By default: ${PACKAGES_REPOSITORY}."
    echo -e ""
    echo -e "        -s,  --store"
    echo -e "                Set the destination absolute path where the OVA file will be stored."
    echo -e "                By default, a output folder will be created in ${OUTPUT_DIR}."
    echo -e ""
    echo -e "        -c,  --checksum"
    echo -e "                Generate OVA checksum."
    echo -e "                Values: [yes|no]. By default: ${CHECKSUM}."
    echo -e ""
    echo -e "        -g,  --debug"
    echo -e "                Set debug mode."
    echo -e "                Values: [yes|no]. By default: ${DEBUG}."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Show this help."
    echo ""
    exit "$1"
}

clean() {
    exit_code=$1

    cd "${scriptpath}"
    vagrant destroy -f
    OVA_VMDK="wazuh-${OVA_VERSION}-disk001.vmdk"
    rm -f "${OVA_VM}" "${OVF_VM}" "${OVA_VMDK}" "${OVA_FIXED}"

    exit "${exit_code}"
}

build_ova() {

    OVA_VM="wazuh-${OVA_VERSION}.ova"
    OVF_VM="wazuh-${OVA_VERSION}.ovf"
    OVA_FIXED="wazuh-${OVA_VERSION}-fixed.ova"

    export PACKAGES_REPOSITORY
    export DEBUG

    if [ -e "${OUTPUT_DIR}/${OVA_VM}" ] || [ -e "${OUTPUT_DIR}/${OVF_VM}" ]; then
        rm -f "${OUTPUT_DIR}"/"${OVA_VM}" "${OUTPUT_DIR}"/"${OVF_VM}"
    fi

    if [ -e "${CHECKSUM_DIR}/${OVA_VM}.sha512" ]; then
        rm -f "${CHECKSUM_DIR}/${OVA_VM}.sha512"
    fi

    # Vagrant will provision the VM with all the software. (See vagrantfile)
    vagrant destroy -f
    vagrant up || clean 1
    vagrant suspend
    echo "Exporting ova"

    # Get machine name
    VM_EXPORT=$(vboxmanage list vms | grep -i vm_wazuh | cut -d "\"" -f2)

    # Create OVA with machine
    vboxmanage export "${VM_EXPORT}" -o "${OVA_VM}" \
    --vsys 0 \
    --product "Wazuh v${OVA_VERSION} OVA" \
    --producturl "https://packages.wazuh.com/vm/wazuh-${OVA_VERSION}.ova" \
    --vendor "Wazuh, inc <info@wazuh.com>" --vendorurl "https://wazuh.com" \
    --version "$OVA_VERSION" --description "Wazuh enhances security visibility in your infrastructure by monitoring endpoints at the operating system and application levels. Its capabilities include log analysis, file integrity monitoring, intrusion detection, and compliance monitoring." \
    || clean 1

    vagrant destroy -f

    tar -xvf "${OVA_VM}"

    echo "Setting up ova for VMware ESXi"

    # Configure OVA for import to VMWare ESXi
    if [ -n "$(command -v python)" ]; then
        python Ova2Ovf.py -s "${OVA_VM}" -d "${OVA_FIXED}"
    elif [ -n "$(command -v python3)" ]; then
        python3 Ova2Ovf.py -s "${OVA_VM}" -d "${OVA_FIXED}"
    else
        echo "Cannot find python"
        clean 1
    fi
    

    # Make output dir of OVA file
    mkdir -p "${OUTPUT_DIR}"
    mv "${OVA_FIXED}" "${OUTPUT_DIR}"/"${OVA_VM}"

}

main() {

    while [ -n "$1" ]; do

        case $1 in
            "-h" | "--help")
            help 0
        ;;

        "-r" | "--repository")
            if [ -n "$2" ]; then
                if [ "$2" != "prod" ] && [ "$2" != "dev" ] && [ "$2" != "staging" ]; then
                    echo "ERROR: Repository must be: [prod/dev/staging]"
                    help 1
                fi
                PACKAGES_REPOSITORY="$2"
                shift 2
            else
                echo "ERROR: Value must be: [prod/dev/staging]"
                help 1
            fi
        ;;

        "-s" | "--store-path")
            if [ -n "$2" ]; then
                OUTPUT_DIR="$2"
                shift 2
            else
                echo "ERROR: Need store path"
                help 1
            fi
        ;;

        "-g" | "--debug")
            if [ -n "$2" ]; then
                if [ "$2" != "no" ] && [ "$2" != "yes" ]; then
                    echo "ERROR: Debug must be [yes/no]"
                    help 1
                fi
                DEBUG="$2"
                shift 2
            else
                echo "ERROR: Need a value [yes/no]"
                help 1
            fi
        ;;

        "-c"|"--checksum")
            if [ -n "$2" ]; then
                if [ "$2" != "no" ] && [ "$2" != "yes" ]; then
                    echo "ERROR: Checksum must be [yes/no]"
                    help 1
                fi
                CHECKSUM="$2"
                shift 2
            else
                echo "ERROR: Checksum needs a value [yes/no]"
                help 1
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

    [[ ${PACKAGES_REPOSITORY} = "prod" ]] && REPO="production" || REPO="development"

    cp -r ../${UNATTENDED_RESOURCES_FOLDER} .

    OVA_VERSION=$(cat ${VERSION_FILE})
    if [ "${OVA_VERSION:0:1}" == "v" ]; then
        OVA_VERSION=${OVA_VERSION:1}
    fi


    # Build OVA file (no standard)
    echo "Version to build: ${OVA_VERSION} with ${REPO} repository"
    build_ova

    rm -rf ${UNATTENDED_RESOURCES_FOLDER}

    # Standarize OVA
    bash setOVADefault.sh "${scriptpath}" "${OUTPUT_DIR}/${OVA_VM}" "${OUTPUT_DIR}/${OVA_VM}" "${scriptpath}/wazuh_ovf_template" "${OVA_VERSION}"  || clean 1

    if [ "${CHECKSUM}" = "yes" ]; then
        mkdir -p "${CHECKSUM_DIR}"
        cd "${OUTPUT_DIR}" && sha512sum "${OVA_VM}" > "${CHECKSUM_DIR}/${OVA_VM}.sha512"
        echo "Checksum created in ${CHECKSUM_DIR}/${OVA_VM}.sha512"
    fi

    echo "Process finished"
    clean 0

}

main "$@"
