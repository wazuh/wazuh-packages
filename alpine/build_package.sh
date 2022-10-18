#!/bin/bash

# Wazuh package generator
# Copyright (C) 2022, Wazuh Inc.
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
apk_x86_64_builder="apk_agent_builder_x86_64"
apk_aarch64_builder="apk_agent_builder_aarch64"
apk_x86_builder="apk_agent_builder_x86"
apk_armhf_builder="apk_agent_builder_armhf"
apk_ppc64le_builder="apk_agent_builder_ppc64le"
apk_builder_dockerfile="${current_path}/docker"
future="no"
jobs="2"
debug="no"
spec_reference="master"
installation_path="/var/ossec"
aws_region="us-east-1"
local_spec="no"
local_source="no"
private_key_id=""
public_key_id=""

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

build_apk() {
    container_name="$1"
    dockerfile_path="$2"

    # Copy the necessary files
    cp ${current_path}/builder.sh ${dockerfile_path}

    # Build the Docker image
    if [[ ${build_docker} == "yes" ]]; then
        docker build -t ${container_name} ${dockerfile_path} || return 1
    fi

    # Build the Alpine package with a Docker container
    volumes="-v ${outdir}/:/var/local/wazuh:Z"
    if [ "${local_spec}" = "yes" ];then
        volumes="${volumes} -v ${current_path}/..:/root/repository:Z"
        #packages_private_key packages_public_key us-east-1 
    fi

    if [ "${local_source}" != "no" ];then
        volumes="${volumes} -v ${local_source}:/wazuh:Z"
    fi

    docker run -t --rm ${volumes} \
        ${container_name} ${reference} ${architecture} ${revision} ${jobs} \
        ${installation_path} ${debug} ${spec_reference} ${local_spec} \
        ${local_source} ${future} ${aws_region} ${private_key_id} \
        ${public_key_id} || return 1


    echo "Package $(ls -Art ${outdir} | tail -n 1) added to ${outdir}."

    return 0
}

build() {
    build_name=""
    file_path=""
    if [ "${architecture}" = "x86_64" ] || [ "${architecture}" = "amd64" ]; then
        architecture="x86_64"
        build_name="${apk_x86_64_builder}"
    elif [ "${architecture}" = "arm64" ] || [ "${architecture}" = "aarch64" ] || \
        [ "${architecture}" = "arm64v8" ]; then
        architecture="aarch64"
        build_name="${apk_arm64v8_builder}"
    elif [ "${architecture}" = "i386" ] || [ "${architecture}" = "x86" ]; then
        architecture="x86"
        build_name="${apk_x86_builder}"
    elif [ "${architecture}" = "armhf" ] || [ "${architecture}" = "arm32" ] || \
          [ "${architecture}" = "arm32v7" ]; then
        architecture="armhf"
        build_name="${apk_armhf_builder}"
    elif [ "${architecture}" = "ppc64le" ] || [ "${architecture}" = "ppc" ]; then
        architecture="ppc64le"
        build_name="${apk_ppc64le_builder}"
    else
        echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too)"
        return 1
    fi
    file_path="${apk_builder_dockerfile}/${architecture}"
    build_apk ${build_name} ${file_path} || return 1

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --reference <ref>      [Required] Select Git branch or tag from wazuh repository."
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [x86_64]."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug                [Optional] Build the binaries with debug symbols. By default: no."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --sources <path>           [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo "    --packages-reference <ref> [Optional] Select Git branch or tag from wazuh-packages repository. e.g ${spec_reference}"
    echo "    --dev                      [Optional] Use the SPECS files stored in the host instead of downloading them from GitHub."
    echo "    --future                   [Optional] Build test future package 99.99.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}


main() {
    while [ -n "$1" ]
    do
        case "$1" in
        "-h"|"--help")
            help 0
            ;;
        "-b"|"--reference")
            if [ -n "$2" ]; then
                reference="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]; then
                architecture="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "$2" ]; then
                jobs="$2"
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
        "-p"|"--path")
            if [ -n "$2" ]; then
                installation_path="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-d"|"--debug")
            debug="yes"
            shift 1
            ;;
        "--packages-reference"|"--packages-branch")
            if [ -n "$2" ]; then
                spec_reference="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--dev")
            local_spec="yes"
            shift 1
            ;;
        "--sources")
            if [ -n "$2" ]; then
                local_source="$2"
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

    build || clean 1

    clean 0
}

main "$@"
