#!/bin/bash

# Wazuh package generator
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

current_path="$( cd $(dirname $0) ; pwd -P )"
architecture="amd64"
outdir="${current_path}/output"
revision="1"
build_docker="yes"
deb_amd64_builder="deb_dashboard_builder_amd64"
deb_builder_dockerfile="${current_path}/docker"
future="no"
base_cmd=""
url=""
build_base="yes"

trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${dockerfile_path}/{*.sh,*.tar.gz,wazuh-*}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

build_deb() {
    container_name="$1"
    dockerfile_path="$2"

    if [ "${repository}" ];then
        url="${repository}"
    fi

    # Copy the necessary files
    cp ${current_path}/builder.sh ${dockerfile_path}

    if [ "${build_base}" == "yes" ];then
        # Base generation
        if [ "${future}" == "yes" ];then
            base_cmd+="--future "
        fi
        if [ "${reference}" ];then
            base_cmd+="--reference ${reference}"
        fi
        if [ "${url}" ];then
            base_cmd+="--app-url ${url}"
        fi
        ../base/generate_base.sh -s ${outdir} -r ${revision} ${base_cmd}
    else
        if [ "${reference}" ];then
            version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${reference}/VERSION | cat)
        else
            version=$(cat ${current_path}/../../../VERSION)
        fi
        basefile="${outdir}/wazuh-dashboard-base-${version}-${revision}-linux-x64.tar.xz"
        if ! test -f "${basefile}"; then
            echo "Did not find expected Wazuh dashboard base file: ${basefile} in output path. Exiting..."
            exit 1
        fi
    fi

    # Build the Docker image
    if [[ ${build_docker} == "yes" ]]; then
        docker build -t ${container_name} ${dockerfile_path} || return 1
    fi

    # Build the Debian package with a Docker container
    volumes="-v ${outdir}/:/tmp:Z"
    if [ "${reference}" ];then
        docker run -t --rm ${volumes} \
            ${container_name} ${architecture} ${revision} \
            ${future} ${url} ${reference} || return 1
    else
        docker run -t --rm ${volumes} \
            -v ${current_path}/../../..:/root:Z \
            ${container_name} ${architecture} ${revision} \
            ${future} ${url}  || return 1
    fi

    echo "Package $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

build() {
    build_name=""
    file_path=""
    if [ "${architecture}" = "x86_64" ] || [ "${architecture}" = "amd64" ]; then
        architecture="amd64"
        build_name="${deb_amd64_builder}"
        file_path="${deb_builder_dockerfile}/${architecture}"
    else
        echo "Invalid architecture. Choose: amd64 (x86_64 is accepted too)"
        return 1
    fi
    build_deb ${build_name} ${file_path} || return 1

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64]."
    echo "    --app-url <url>            [Optional] Set the repository from where the Wazuh plugin should be downloaded. By default, will be used pre-release."
    echo "    -b, --build-base <yes/no>  [Optional] Build a new base or use a existing one. By default, yes."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    --reference <ref>          [Optional] wazuh-packages branch to download SPECs, not used by default."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --future                   [Optional] Build test future package 99.99.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}


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
        "--app-url")
            if [ -n "$2" ]; then
                repository="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-b"|"--build-base")
            if [ -n "${2}" ]; then
                build_base="${2}"
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--revision")
            if [ -n "${2}" ]; then
                revision="${2}"
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
        "--dont-build-docker")
            build_docker="no"
            shift 1
            ;;
        "--future")
            future="yes"
            shift 1
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

    build || clean 1

    clean 0
}

main "$@"
