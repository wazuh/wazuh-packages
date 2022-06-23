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
opensearch_version="1.2.0"
architecture="x64"
outdir="${current_path}/output"
revision="1"
future="no"

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

    # Build the Docker image
    docker build -t ${container_name} ${dockerfile_path} || return 1

    if [ "${reference}" ];then
        docker run -t --rm -v ${outdir}/:/tmp/output:Z \
            ${container_name} ${opensearch_version} ${future} ${revision} ${architecture} ${reference} || return 1
    else
        docker run -t --rm -v ${outdir}/:/tmp/output:Z \
            -v ${current_path}/../../..:/root:Z \
            ${container_name} ${opensearch_version} ${future} ${revision} ${architecture} || return 1
    fi

    echo "Base file $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

# -----------------------------------------------------------------------------

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [x64] or [arm64]."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -v, --version <path>       [Optional] The OpenSearch-dashboards Version. By default, ${opensearch_version}"
    echo "    --reference <ref>          [Optional] wazuh-packages branch or tag"
    echo "    --future                   [Optional] Build test future package 99.99.0 Used for development purposes."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default ${revision}"
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
        "-a"|"--architecture")
            if [ -n "${2}" ]; then
                architecture="${2}"
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
        "-v"|"--version")
            if [ -n "${2}" ]; then
                opensearch_version="${2}"
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