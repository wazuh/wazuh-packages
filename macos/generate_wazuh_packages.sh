#!/bin/bash
# Program to build and package OSX wazuh-agent
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
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
ENTITLEMENTS_PATH="${CURRENT_PATH}/entitlements.plist"
INSTALLATION_PATH="/Library/Ossec"    # Installation path
VERSION=""                            # Default VERSION (branch/tag)
REVISION="1"                          # Package revision.
BRANCH_TAG="master"                   # Branch that will be downloaded to build package.
DESTINATION="${CURRENT_PATH}/output/" # Where package will be stored.
JOBS="2"                              # Compilation jobs.
DEBUG="no"                            # Enables the full log by using `set -exf`.
CHECKSUMDIR=""                        # Directory to store the checksum of the package.
CHECKSUM="no"                         # Enables the checksum generation.
CERT_APPLICATION_ID=""                # Apple Developer ID certificate to sign Apps and binaries.
CERT_INSTALLER_ID=""                  # Apple Developer ID certificate to sign pkg.
KEYCHAIN=""                           # Keychain where the Apple Developer ID certificate is.
KC_PASS=""                            # Password of the keychain.
NOTARIZE="no"                         # Notarize the package for macOS Catalina.
DEVELOPER_ID=""                       # Apple Developer ID.
ALTOOL_PASS=""                        # Temporary Application password for altool.
pkg_name=""

trap ctrl_c INT

function clean_and_exit() {
    exit_code=$1
    rm -f ${AGENT_PKG_FILE} ${CURRENT_PATH}/package_files/*.sh
    rm -rf "${SOURCES_DIRECTORY}"
    ${CURRENT_PATH}/uninstall.sh
    exit ${exit_code}
}

function ctrl_c() {
    clean_and_exit 1
}


function notarize_pkg() {

    # Notarize the macOS package
    sleep_time="120"
    build_timestamp="$(date +"%m%d%Y%H%M%S")"
    if [ "${NOTARIZE}" = "yes" ]; then
        if sudo xcrun altool --notarize-app --primary-bundle-id "com.wazuh.agent.${VERSION}.${REVISION}.${build_timestamp}" \
            --username "${DEVELOPER_ID}" --password "${ALTOOL_PASS}" --file ${DESTINATION}/${pkg_name} > request_info.txt ; then
            echo "The package ${DESTINATION}/${pkg_name} was successfully upload for notarization."
            echo "Waiting ${sleep_time}s to get the results"
            sleep ${sleep_time}

            uuid="$(grep -i requestuuid request_info.txt | cut -d' ' -f 3)"

            # Check notarization status
            xcrun altool --notarization-info ${uuid} -u "${DEVELOPER_ID}" --password "${ALTOOL_PASS}" > request_result.txt
            until ! grep -qi "in progress" request_result.txt ; do
                echo "Package is not notarized yet. Waiting ${sleep_time}s"
                sleep ${sleep_time}
                xcrun altool --notarization-info ${uuid} -u "${DEVELOPER_ID}" --password "${ALTOOL_PASS}" > request_result.txt
            done

            echo "Notarization ticket:"
            cat request_result.txt

            if grep "Status: success" request_result.txt > /dev/null 2>&1 ; then
                echo "Package is notarized and ready to go."
                echo "Adding the ticket to the package."
                if xcrun stapler staple -v ${DESTINATION}/${pkg_name} ; then
                    echo "Ticket added. Ready to release the package."
                    return 0
                else
                    echo "Something went wrong while adding the package."
                    clean_and_exit 1
                fi
            else

                echo "The package couldn't be notarized."
                echo "Check notarization ticket for more info."
                clean_and_exit 1
            fi

        else
            echo "Error while uploading the app to be notarized."
            clean_and_exit 1
        fi
    fi

    return 0
}

function sign_binaries() {
    if [ ! -z "${KEYCHAIN}" ] && [ ! -z "${CERT_APPLICATION_ID}" ] ; then
        security -v unlock-keychain -p "${KC_PASS}" "${KEYCHAIN}" > /dev/null
        # Sign every single binary in Wazuh's installation. This also includes library files.
        for bin in $(find ${INSTALLATION_PATH} -exec file {} \; | grep bit | cut -d: -f1); do
            codesign -f --sign "${CERT_APPLICATION_ID}" --entitlements ${ENTITLEMENTS_PATH} --deep --timestamp  --options=runtime --verbose=4 "${bin}"
        done
        security -v lock-keychain "${KEYCHAIN}" > /dev/null
    fi
}

function sign_pkg() {
    if [ ! -z "${KEYCHAIN}" ] && [ ! -z "${CERT_INSTALLER_ID}" ] ; then
        # Unlock the keychain to use the certificate
        security -v unlock-keychain -p "${KC_PASS}" "${KEYCHAIN}"  > /dev/null

        # Sign the package
        productsign --sign "${CERT_INSTALLER_ID}" --timestamp ${DESTINATION}/${pkg_name} ${DESTINATION}/${pkg_name}.signed
        mv ${DESTINATION}/${pkg_name}.signed ${DESTINATION}/${pkg_name}

        security -v lock-keychain "${KEYCHAIN}" > /dev/null
    fi
}

function build_package() {

    # Download source code
    git clone --depth=1 -b ${BRANCH_TAG} ${WAZUH_SOURCE_REPOSITORY} "${WAZUH_PATH}"

    get_pkgproj_specs

    VERSION=$(cat ${WAZUH_PATH}/src/VERSION | cut -d "-" -f1 | cut -c 2-)

    if [ -d "${INSTALLATION_PATH}" ]; then

        echo "\nThe wazuh agent is already installed on this machine."
        echo "Removing it from the system."

        ${CURRENT_PATH}/uninstall.sh
    fi

    packages_script_path=""

    # build the sources
    if [[ "${VERSION}" =~ ^2\. ]]; then
        packages_script_path="package_files/2.x"
    else
        packages_script_path="package_files/${VERSION}"
    fi

    cp ${packages_script_path}/*.sh ${CURRENT_PATH}/package_files/
    ${CURRENT_PATH}/package_files/build.sh "${INSTALLATION_PATH}" "${WAZUH_PATH}" ${JOBS}

    # sign the binaries and the libraries
    sign_binaries

    # create package
    if packagesbuild ${AGENT_PKG_FILE} --build-folder ${DESTINATION} ; then
        echo "The wazuh agent package for MacOS X has been successfully built."
        pkg_name="wazuh-agent-${VERSION}-${REVISION}.pkg"
        sign_pkg
        notarize_pkg
        if [[ "${CHECKSUM}" == "yes" ]]; then
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
    echo "  Build options:"
    echo "    -b, --branch <branch>         [Required] Select Git branch or tag e.g. $BRANCH"
    echo "    -s, --store-path <path>       [Optional] Set the destination absolute path of package."
    echo "    -j, --jobs <number>           [Optional] Number of parallel jobs when compiling."
    echo "    -r, --revision <rev>          [Optional] Package revision that append to version e.g. x.x.x-rev"
    echo "    -c, --checksum <path>         [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package)."
    echo "    -h, --help                    [  Util  ] Show this help."
    echo "    -i, --install-deps            [  Util  ] Install build dependencies (Packages)."
    echo "    -x, --install-xcode           [  Util  ] Install X-Code and brew. Can't be executed as root."
    echo
    echo "  Signing options:"
    echo "    --keychain                    [Optional] Keychain where the Certificates are installed."
    echo "    --keychain-password           [Optional] Password of the keychain."
    echo "    --application-certificate     [Optional] Apple Developer ID certificate name to sign Apps and binaries."
    echo "    --installer-certificate       [Optional] Apple Developer ID certificate name to sign pkg."
    echo "    --notarize                    [Optional] Notarize the package for its distribution on macOS Catalina ."
    echo "    --developer-id                [Optional] Your Apple Developer ID."
    echo "    --altool-password             [Optional] Temporary password to use altool from Xcode."
    echo
    exit "$1"
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
        "--keychain")
            if [ -n "$2" ]; then
                KEYCHAIN="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--keychain-password")
            if [ -n "$2" ]; then
                KC_PASS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--application-certificate")
            if [ -n "$2" ]; then
                CERT_APPLICATION_ID="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--installer-certificate")
            if [ -n "$2" ]; then
                CERT_INSTALLER_ID="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--notarize")
            NOTARIZE="yes"
            shift 1
            ;;
        "--developer-id")
            if [ -n "$2" ]; then
                DEVELOPER_ID="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--altool-password")
            if [ -n "$2" ]; then
                ALTOOL_PASS="$2"
                shift 2
            else
                help 1
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
        build_package
        "${CURRENT_PATH}/uninstall.sh"
    else
        echo "The branch has not been specified. No package will be generated."
        help 1
    fi

    return 0
}

main "$@"
