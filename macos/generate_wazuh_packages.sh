#!/bin/bash
# Program to build and package OSX wazuh-agent
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname ${0}) ; pwd -P )"
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
WAZUH_PATH="${SOURCES_DIRECTORY}/wazuh"
WAZUH_SOURCE_REPOSITORY="https://github.com/wazuh/wazuh"
AGENT_PKG_FILE="${CURRENT_PATH}/package_files/wazuh-agent.pkgproj"
export CONFIG="${WAZUH_PATH}/etc/preloaded-vars.conf"
INSTALLATION_PATH="/Library/Ossec"    # Installation path
VERSION=""                            # Default VERSION (branch/tag)
REVISION="1"                          # Package revision.
BRANCH_TAG="master"                   # Branch that will be downloaded to build package.
DESTINATION="${CURRENT_PATH}/output/" # Where package will be stored.
JOBS="2"                              # Compilation jobs.
DEBUG="no"                            # Enables the full log by using `set -exf`.
CHECKSUMDIR=""
CHECKSUM="no"

function clean_and_exit() {
    exit_code=$1
    rm -f ${AGENT_PKG_FILE} ${CURRENT_PATH}/package_files/*.sh
    rm -rf "${SOURCES_DIRECTORY}"
    ${CURRENT_PATH}/uninstall.sh
    exit ${exit_code}
}

function build_package() {

    VERSION=$(cat ${WAZUH_PATH}/src/VERSION | cut -d "-" -f1 | cut -c 2-)

    if [ -d "${INSTALLATION_PATH}" ]; then

        echo "\nThe wazuh agent is already installed on this machine."
        echo "Removing it from the system."

        ${CURRENT_PATH}/uninstall.sh
    fi

    packages_script_path=""

    # build the sources
    if [[ "${VERSION}" =~ "2." ]]; then
        packages_script_path="package_files/2.x"
    else
        packages_script_path="package_files/${VERSION}"
    fi

    cp ${packages_script_path}/*.sh ${CURRENT_PATH}/package_files/
    ${CURRENT_PATH}/package_files/build.sh "${INSTALLATION_PATH}" "${WAZUH_PATH}" ${JOBS}

    # create package
    if packagesbuild ${AGENT_PKG_FILE} --build-folder ${DESTINATION} ; then
        echo "The wazuh agent package for MacOS X has been successfully built."
        if [[ "${CHECKSUM}" == "yes" ]]; then
            pkg_name="wazuh-agent-${VERSION}-${REVISION}.pkg"
            mkdir -p ${CHECKSUMDIR}
            cd ${DESTINATION} && shasum -a512 "${pkg_name}" > "${CHECKSUMDIR}/${pkg_name}.sha512"
        fi
        clean_and_exit 0
    else
        echo "ERROR: something went wrong while building the package."
        clean_and_exit 1
    fi
}

function help() {

    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. $BRANCH"
    echo "    -s, --store-path <path>   [Optional] Set the destination absolute path of package."
    echo "    -j, --jobs <number>       [Optional] Number of parallel jobs when compiling."
    echo "    -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev"
    echo "    -c, --checksum <path>     [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    -h, --help                [  Util  ] Show this help."
    echo "    -i, --install-deps        [  Util  ] Install build dependencies (Packages)."
    echo "    -x, --install-xcode       [  Util  ] Install X-Code and brew. Can't be executed as root."
    echo
    exit "$1"
}

function download_source(){

    mkdir -p "${SOURCES_DIRECTORY}"

    if git clone --depth=1 -b ${BRANCH_TAG} ${WAZUH_SOURCE_REPOSITORY} "${WAZUH_PATH}" ; then
        echo "Successfully downloaded source code from GitHub from ${BRANCH_TAG}"
    else
        echo "Error: Source code from ${BRANCH_TAG} could not be downloaded"
        exit 1
    fi
}

function get_pkgproj_specs() {

    VERSION=$(< "${WAZUH_PATH}/src/VERSION"  cut -d "-" -f1 | cut -c 2-)

    major="$(echo "$VERSION" | cut -d'.' -f 1)"
    major_path="specs/${major}.x"

    if [ ! -d "${CURRENT_PATH}/${major_path}" ]; then
        echo "Warning: directory for Wazuh ${major}.x does not exists. Check the version selected."
    fi

    pkg_file="${major_path}/wazuh-agent-${VERSION}.pkgproj"

    if [ ! -f "${pkg_file}" ]; then
        echo "Warning: the file ${pkg_file} does not exists. Check the version selected."
        exit 1
    else
        echo "Modifiying ${pkg_file} to match revision."
        sed -i -e "s:${VERSION}-.*<:${VERSION}-${REVISION}<:g" "${pkg_file}"
        cp "${pkg_file}" "${AGENT_PKG_FILE}"
    fi

    return 0
}

function testdep() {

    if command -v packagesbuild ; then
        return 0
    else
        echo "Error: packagesbuild not found. Download and install dependencies."
        echo "Use $0 -i for install it."
        exit 1
    fi
}

function install_deps() {

    # Install packagesbuild tool
    curl -O http://s.sudre.free.fr/Software/files/Packages.dmg

    hdiutil attach Packages.dmg

    cd /Volumes/Packages*/packages/

    if installer -package Packages.pkg -target / ; then
        echo "Packagesbuild was correctly installed."
    else
        echo "Something went wrong installing packagesbuild."
    fi

    exit 0
}

function install_xcode() {

    # Install brew tool. Brew will install X-Code if it is not already installed in the host.
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

    exit 0
}

function check_root() {

    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        echo
        exit 1
    fi
}

function main() {

    BUILD="no"
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH_TAG="$2"
                BUILD=yes
                shift 2
            else
                help 1
            fi
            ;;
        "-s"|"--store-path")
            if [ -n "$2" ]; then
                DESTINATION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "$2" ]; then
                JOBS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--revision")
            if [ -n "$2" ]; then
                REVISION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-i"|"--install-deps")
            check_root
            install_deps
            ;;
        "-x"|"--install-xcode")
            install_xcode
            ;;
        "-v"|"--verbose")
            DEBUG="yes"
            shift 1
            ;;
        "-c"|"--checksum")
            if [ -n "$2" ]; then
                CHECKSUMDIR="$2"
                CHECKSUM="yes"
                shift 2
            else
                CHECKSUM="yes"
                shift 1
            fi
            ;;
        *)
            help 1
        esac
    done

    if [ ${DEBUG} = "yes" ]; then
        set -exf
    fi

    testdep

    if [ -z "${CHECKSUMDIR}" ]; then
        CHECKSUMDIR="${DESTINATION}"
    fi

    if [[ "$BUILD" != "no" ]]; then
        check_root
        download_source
        get_pkgproj_specs
        build_package
        "${CURRENT_PATH}/uninstall.sh"
    else
        echo "The branch has not been specified. No package will be generated."
        help 1
    fi

    return 0
}

main "$@"
