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
apk_armv7_builder="apk_agent_builder_armv7"
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
    docker_flags="-t --rm"

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

    if [ "${architecture}" = "armhf" ] || [ "${architecture}" = "armv7" ]; then
        docker_flags="${docker_flags} --security-opt seccomp=unconfined"
    fi

    docker run ${docker_flags} ${volumes} \
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
        build_name="${apk_aarch64_builder}"
    elif [ "${architecture}" = "i386" ] || [ "${architecture}" = "x86" ]; then
        architecture="x86"
        build_name="${apk_x86_builder}"
    elif [ "${architecture}" = "armhf" ] || [ "${architecture}" = "arm32" ]; then
        architecture="armhf"
        build_name="${apk_armhf_builder}"
    elif [ "${architecture}" = "armv7" ] || [ "${architecture}" = "arm32v7" ]; then
        architecture="armv7"
        build_name="${apk_armv7_builder}"
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
    echo -e ""
    echo -e "NAME"
    echo -e "       $(basename "$0") - Build Alpine package on different architectures."
    echo -e ""
    echo -e "SYNOPSYS"
    echo -e "        $(basename "$0") [OPTIONS]"
    echo -e ""
    echo -e "OPTIONS"
    echo -e "       -b, --reference <ref>"
    echo -e "               [Required] Select Git branch or tag from wazuh repository."
    echo -e ""
    echo -e "       -a, --architecture <arch>"
    echo -e "               [Optional] Target architecture of the package [x86_64/x86/armhf/armv7/aarch64/ppc64le]."
    echo -e ""
    echo -e "       -j, --jobs <number>"
    echo -e "               [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo -e ""
    echo -e "       -r, --revision <rev>"
    echo -e "               [Optional] Package revision [Only numeric values allowed]. By default: 1."
    echo -e ""
    echo -e "       -s, --store <path>"
    echo -e "               [Optional] Set the destination path of package. By default, an output folder will be created."
    echo -e ""
    echo -e "       -p, --path <path>"
    echo -e "               [Optional] Installation path for the package. By default: /var/ossec."
    echo -e ""
    echo -e "       -d, --debug"
    echo -e "               [Optional] Build the binaries with debug symbols. By default: no."
    echo -e ""
    echo -e "       --dont-build-docker"
    echo -e "               [Optional] Locally built docker image will be used instead of generating a new one."
    echo -e ""
    echo -e "       --sources <path>"
    echo -e "               [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo -e ""
    echo -e "       --packages-reference <ref>"
    echo -e "               [Optional] Select Git branch or tag from wazuh-packages repository. e.g ${spec_reference}"
    echo -e ""
    echo -e "       --dev"
    echo -e "               [Optional] Use the SPECS files stored in the host instead of downloading them from GitHub."
    echo -e ""
    echo -e "       --future"
    echo -e "               [Optional] Build test future package {MAJOR}.30.0 Used for development purposes."
    echo -e ""
    echo -e "       -h, --help"
    echo -e "               Show this help."
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
        "-t"|"--target")
            if [ -n "$2" ]; then
            echo "-t|--target has been disabled, It will set as agent by default."
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
