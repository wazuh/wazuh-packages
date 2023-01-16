#!/bin/bash

# Wazuh package generator
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

wazuh_puppet_branch=""
wazuh_forge_token=""
current_path="$( cd $(dirname $0) ; pwd -P )"
dockerfile_path="${current_path}/Docker"
container_name="puppet_module_builder"

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

    docker run -t --rm ${container_name} ${wazuh_puppet_branch} ${wazuh_forge_token} || return 1

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <path>        [Required] Set the destination path of package. By default, an output folder will be created."
    echo "    -f, --forge-token <ref>    [Required] wazuh-packages branch or tag"
    echo "    -h, --help                 Show this help."
    echo
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
        "-f"|"--forge-token")
            if [ -n "${2}" ]; then
                wazuh_forge_token="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    if [ -z "${wazuh_puppet_branch}" ] || [ -z "${wazuh_forge_token}" ]; then
        echo "You must enter the 2 parameters, --branch and --forge-token"
        exit $1
    fi

    build || clean 1

    clean 0
}

main "$@"