#!/bin/bash

# Wazuh package generator
# Copyright (C) 2023, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

wazuh_puppet_branch=""
current_path="$( cd $(dirname $0) ; pwd -P )"
dockerfile_path="${current_path}/Docker"
container_name="puppet_module_builder"
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

    docker run -t --rm -v ${outdir}/:/tmp/output:Z ${container_name} ${wazuh_puppet_branch} || return 1

    echo "Puppet module file $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "${0}") - Build Wazuh Puppet module."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -b, --branch <branch>"
    echo -e "                Enter the branch or tag of the wazuh-puppet repository from which you want to build the module."
    echo -e ""
    echo -e "        -s, --store <path>"
    echo -e "                [Optional] Set the destination path of package. By default, an output folder will be created."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    exit $1
}

# -----------------------------------------------------------------------------

main() {
    while [ -n "${1}" ]
    do
        case "${1}" in
        "-h"|"--help")
            help 0
            ;;
        "-b"|"--branch")
            if [ -n "${2}" ]; then
                wazuh_puppet_branch="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        "-s"|"--store")
            if [ -n "${2}" ]; then
                outdir="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    if [ -z "${wazuh_puppet_branch}" ];  then
        echo "Branch cannot be empty"
        exit $1
    fi

    build || clean 1

    clean 0
}

main "$@"
