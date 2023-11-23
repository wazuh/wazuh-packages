#!/bin/bash

# Wazuh package generator
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

current_path="$( cd $(dirname $0) ; pwd -P )"
architecture="x86_64"
outdir="${current_path}/output"
revision="1"
build_docker="yes"
rpm_x86_builder="rpm_dashboard_builder_x86"
rpm_builder_dockerfile="${current_path}/docker"
future="no"
base_cmd=""
plugin_main=""
plugin_updates=""
plugin_core=""
build_base="yes"
have_main=false
have_updates=false
have_core=false
version=""

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

set_version() {
    if [ "${reference}" ];then
        version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${reference}/VERSION | cat)
    else
        version=$(cat ${current_path}/../../../VERSION)
    fi
}

build_rpm() {
    container_name="$1"
    dockerfile_path="$2"

    if [ "${plugin_main_reference}" ];then
        plugin_main="${plugin_main_reference}"
    fi
    if [ "${plugin_updates_reference}" ];then
        plugin_updates="${plugin_updates_reference}"
    fi
    if [ "${plugin_core_reference}" ];then
        plugin_core="${plugin_core_reference}"
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
        if [ "${plugin_main_reference}" ];then
            base_cmd+="--app-url ${plugin_main_reference}"
        fi
        ../base/generate_base.sh -s ${outdir} -r ${revision} ${base_cmd}
    else
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

    # Build the RPM package with a Docker container
    volumes="-v ${outdir}/:/tmp:Z"
    if [ "${reference}" ];then
        docker run -t --rm ${volumes} \
            ${container_name} ${architecture} ${revision} \
            ${future} ${plugin_main} ${plugin_updates} ${plugin_core} ${reference} || return 1
    else
        docker run -t --rm ${volumes} \
            -v ${current_path}/../../..:/root:Z \
            ${container_name} ${architecture} \
            ${revision} ${future} ${plugin_main} ${plugin_updates} ${plugin_core} || return 1
    fi

    echo "Package $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

build() {
    build_name=""
    file_path=""
    if [ "${architecture}" = "x86_64" ] || [ "${architecture}" = "amd64" ]; then
        architecture="x86_64"
        build_name="${rpm_x86_builder}"
        file_path="${rpm_builder_dockerfile}/${architecture}"
    else
        echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too)"
        return 1
    fi
    build_rpm ${build_name} ${file_path} || return 1

    return 0
}

help() {
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Build Wazuh dashboard base file."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") -a | -m | -u | -c | -s | -b | -f | -r | -h"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a, --architecture <arch>"
    echo -e "                [Optional] Target architecture of the package [x86_64]."
    echo -e ""
    echo -e "        -m, --main-app <URL>"
    echo -e "                [Optional] Wazuh main plugin URL."
    echo -e ""
    echo -e "        -u, --updates-app <URL>"
    echo -e "                [Optional] Wazuh Check Updates plugin URL."
    echo -e ""
    echo -e "        -c, --core-app <URL>"
    echo -e "                [Optional] Wazuh Core plugin URL."
    echo -e ""
    echo -e "        -b, --build-base <yes/no>"
    echo -e "                [Optional] Build a new base or use a existing one. By default, yes."
    echo -e ""
    echo -e "        -r, --revision <rev>"
    echo -e "                [Optional] Package revision. By default: 1."
    echo -e ""
    echo -e "        -s, --store <path>"
    echo -e "                [Optional] Set the destination path of package. By default, an output folder will be created."
    echo -e ""
    echo -e "        --reference <ref>"
    echo -e "                [Optional] wazuh-packages branch to download SPECs, not used by default."
    echo -e ""
    echo -e "        --dont-build-docker"
    echo -e "                [Optional] Locally built docker image will be used instead of generating a new one."
    echo -e ""
    echo -e "        --future"
    echo -e "                [Optional] Build test future package 99.99.0 Used for development purposes."
    echo -e ""
    echo -e "        -h, --help"
    echo -e "                Show this help."
    echo -e ""
    exit $1
}


main() {
    while [ -n "$1" ]
    do
        case "$1" in
        "-h"|"--help")
            help 0
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]; then
                architecture="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-m"|"--main-app-url")
            if [ -n "$2" ]; then
                plugin_main_reference="$2"
                have_main=true
                shift 2
            else
                help 1
            fi
            ;;
        "-u"|"--updates-app-url")
            if [ -n "$2" ]; then
                plugin_updates_reference="$2"
                have_updates=true
                shift 2
            else
                help 1
            fi
            ;;
        "-c"|"--core-app-url")
            if [ -n "$2" ]; then
                plugin_core_reference="$2"
                have_core=true
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
            if [ -n "$2" ]; then
                revision="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--reference")
            if [ -n "$2" ]; then
                reference="$2"
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
            if [ -n "$2" ]; then
                outdir="$2"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done


    set_version

    if [ ! "${plugin_main_reference}" ] && [ ! "${plugin_updates_reference}" ] && [ ! "${plugin_core_reference}" ]; then
        echo "No Wazuh plugins have been defined, ${version} pre-release development packages with revision ${revision} will be used."
    elif [[ ${have_main} != ${have_updates} ]] || [[ ${have_updates} != ${have_core} ]]; then
        echo "The -m, -u, and -c options must be used together."
        exit 1
    fi

    build || clean 1

    clean 0
}

main "$@"
