#!/bin/bash

# Wazuh package generator
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e


reference=""
current_path="$( cd $(dirname $0) ; pwd -P )"
dockerfile_path="${current_path}/docker"
container_name="dashboard_base_builder"
architecture="x64"
outdir="${current_path}/output"
revision="1"
future="no"
url=""

# -----------------------------------------------------------------------------

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${dockerfile_path}/{*.sh,*.tar.xz,*-dashboards-*}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

# -----------------------------------------------------------------------------

build() {

    # Copy the necessary files
    cp ${current_path}/builder.sh ${dockerfile_path}

    if [ "${repository}" ];then
        url="${repository}"
    fi

    # Build the Docker image
    docker build -t ${container_name} ${dockerfile_path} || return 1

    if [ "${reference}" ];then
        docker run -t --rm -v ${outdir}/:/tmp/output:Z \
            ${container_name} ${architecture} ${revision} ${future} ${url} ${reference}  || return 1
    else
        docker run -t --rm -v ${outdir}/:/tmp/output:Z \
            -v ${current_path}/../../..:/root:Z \
            ${container_name} ${architecture} ${revision} ${future} ${url} || return 1
    fi

    echo "Base file $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Build Wazuh dashboard base file."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") -a | -s | -b | -f | -r | -h"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        --app-url <url>"
    echo -e "                [Optional] Set the repository from where the Wazuh plugin should be downloaded."
    echo -e ""
    echo -e "        -s, --store <path>"
    echo -e "                [Optional] Set the destination path of package. By default, an output folder will be created."
    echo -e ""
    echo -e "        --reference <ref>"
    echo -e "                [Optional] wazuh-packages branch or tag."
    echo -e ""
    echo -e "        --future"
    echo -e "                [Optional] Build test future package. Used for development purposes."
    echo -e ""
    echo -e "        -r, --revision <rev>"
    echo -e "                [Optional] Package revision."
    echo -e ""
    echo -e "        -h, --help"
    echo -e "                Show this help."
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
        "--app-url")
            if [ -n "$2" ]; then
                repository="$2"
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
        "--reference")
            if [ -n "${2}" ]; then
                reference="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        "--future")
            future="yes"
            shift 1
            ;;
        "-r"|"--revision")
            if [ -n "${2}" ]; then
                revision="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    build || clean 1

    clean 0
}

main "$@"