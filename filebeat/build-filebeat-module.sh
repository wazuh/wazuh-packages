#!/bin/bash

# Wazuh package generator
# Copyright (C) 2023, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

wazuh_branch=""
filename="wazuh-filebeat-0.2.tar.gz"
current_path="$( cd $(dirname $0) ; pwd -P )"
dockerfile_path="${current_path}/docker"
container_name="filebeat_module_builder"
outdir="${current_path}/output"

# -----------------------------------------------------------------------------

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${dockerfile_path}/*.sh

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

# -----------------------------------------------------------------------------

build() {

    # Copy the necessary files
    cp ${current_path}/build.sh ${dockerfile_path}

    # Build the Docker image
    docker build -t ${container_name} ${dockerfile_path} || return 1

    docker run -t --rm -v ${outdir}/:/tmp/output:Z ${container_name} \
        ${wazuh_branch} ${filename} || return 1

    echo "Filebeat module file $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "${0}") - Build Wazuh Filebeat module."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -f, --filename <filename>"
    echo -e "                [Optional] Enter the name of module file. By default, wazuh-filebeat-0.2.tar.gz"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -s, --store <path>"
    echo -e "                [Optional] Set the destination path of package. By default, an output folder will be created."
    echo -e ""
    echo -e "        -w, --wazuh-branch <branch>"
    echo -e "                Enter the branch or tag of the Wazuh repository from which you want to build the module."
    echo -e ""
    exit $1
}

# -----------------------------------------------------------------------------

main() {
    while [ -n "${1}" ]
    do
        case "${1}" in
        "-f"|"--filename")
            if [ -n "${2}" ]; then
                filename="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-s"|"--store")
            if [ -n "${2}" ]; then
                outdir="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        "-w"|"--wazuh-branch")
            if [ -n "${2}" ]; then
                wazuh_branch="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    if [ -z "${wazuh_branch}" ];  then
        echo "Wazuh branch cannot be empty"
        exit $1
    fi

    build || clean 1

    clean 0
}

main "$@"
