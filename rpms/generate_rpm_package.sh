#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Constants
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
RPM_X86_BUILDER="rpm_builder_x86"
RPM_I386_BUILDER="rpm_builder_i386"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/6"
LEGACY_RPM_X86_BUILDER="rpm_legacy_builder_x86"
LEGACY_RPM_I386_BUILDER="rpm_legacy_builder_i386"
LEGACY_RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/5"
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
API_SOURCE_REPOSITORY="https://github.com/wazuh/wazuh-api"
WAZUH_SOURCE_REPOSITORY="https://github.com/wazuh/wazuh"
BRAND="wazuh"
PACKAGE_EXTENSION="rpm"
LEGACY_TAR_FILE="${LEGACY_RPM_BUILDER_DOCKERFILE}/i386/centos-5-i386.tar.gz"
TAR_URL="https://packages-dev.wazuh.com/utils/centos-5-i386-build/centos-5-i386.tar.gz"

if command -v curl > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="curl ${TAR_URL} -o ${LEGACY_TAR_FILE} -s"
elif command -v wget > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="wget ${TAR_URL} -o ${LEGACY_TAR_FILE} -q"
fi


function build_package() {
    local TARGET="$1"
    local VERSION="$2"
    local REVISION="$3"
    local ARCHITECTURE="$4"
    local DESTINATION="$5"
    local CONTAINER_NAME="$6"
    local DOCKERFILE_PATH="$7"
    local JOBS="$8"
    local INSTALLATION_PATH="$9"
    local DEBUG="${10}"
    local CHECKSUM="${11}"

    # Download the legacy tar file if it is needed
    if [ "${CONTAINER_NAME}" == "${LEGACY_RPM_I386_BUILDER}" ] && [ ! -f "${LEGACY_TAR_FILE}" ]; then
        ${DOWNLOAD_TAR}
    fi

    local CHECKSUM_PATH="../checksum"

    if [ "${LEGACY}" == "yes" ]; then
        mkdir ${DESTINATION}/${CHECKSUM_PATH}
        CHECKSUM_PATH="../../../checksum"
    fi

    # Build the RPM package with a Docker container
    docker run -t --rm -v ${DESTINATION}:/var/local/wazuh \
        -v ${DESTINATION}/${CHECKSUM_PATH}:/var/local/wazuh/checksum \
        -v ${SOURCES_DIRECTORY}:/build_wazuh/wazuh-${TARGET}-${VERSION} \
        ${CONTAINER_NAME} ${TARGET} ${VERSION} ${ARCHITECTURE} \
        ${JOBS} ${REVISION} ${INSTALLATION_PATH} ${DEBUG} ${CHECKSUM}|| exit 1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.spec} ${SOURCES_DIRECTORY}

    echo "Package ${BRAND}-${TARGET}-${VERSION}-${REVISION}.src.${PACKAGE_EXTENSION} added to $DESTINATION."
    echo "Package ${BRAND}-${TARGET}-${VERSION}-${REVISION}.${ARCHITECTURE}.${PACKAGE_EXTENSION} added to $DESTINATION."

    return 0
}



function build_container() {
    local TARGET="$1"
    local VERSION="$2"
    local ARCHITECTURE="$3"
    local CONTAINER_NAME="$4"
    local DOCKERFILE_PATH="$5"

    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    cp SPECS/$VERSION/wazuh-$TARGET-$VERSION.spec ${DOCKERFILE_PATH}/wazuh.spec

    # Download the legacy tar file if it is needed
    if [ "${CONTAINER_NAME}" == "${LEGACY_RPM_I386_BUILDER}" ] && [ ! -f "${LEGACY_TAR_FILE}" ]; then
        ${DOWNLOAD_TAR}
    fi

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}

    return 0
}

function help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. $BRANCH"
    echo "    -s, --store <path>        [Required] Set the destination path of package."
    echo "    -t, --target <target>     [Required] Target package to build [manager/api/agent]."
    echo "    -a, --architecture <arch> [Required] Target architecture of the package [x86_64/i386]."
    echo "    -r, --revision <rev>      [Required] Package revision that append to version e.g. x.x.x-rev"
    echo "    -l, --legacy              [Optional] Build package for CentOS 5."
    echo "    -j, --jobs <number>       [Optional] Number of parallel jobs when compiling."
    echo "    -p, --path <path>         [Optional] Installation path for the package. By default: /var."
    echo "    -d, --debug               [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -k, --checksum            [Optional] Generate checksum"
    echo "    -h, --help                Show this help."
    echo
    exit $1
}


function main() {
    # Variables that can change
    local BRANCH=""                       # Branch that will be downloaded to build package.
    local DESTINATION=""                  # Where package will be stored.
    local TARGET=""                       # Compilation target.
    local ARCHITECTURE=""                 # Architecture of the target package.
    local REVISION=""                     # Aditional name of package.
    local JOBS="2"                        # Compilation jobs.
    local INSTALLATION_PATH="/var"  # Path where package will be installed bu default.
    local VERSION=""
    local SOURCE_REPOSITORY=""
    local CONTAINER_NAME=""
    local DOCKERFILE_PATH=""
    local DEBUG="no"
    local CHECKSUM="no"

    local HAVE_BRANCH=false
    local HAVE_DESTINATION=false
    local HAVE_TARGET=false
    local HAVE_ARCHITECTURE=false
    local HAVE_REVISION=false

    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]
            then
#                BRANCH="$(echo $2 | cut -d'/' -f2)"
                local BRANCH="$2"
                local HAVE_BRANCH=true
                shift 2
            else
                help 1
            fi
            ;;
        "-s"|"--store")
            if [ -n "$2" ]
            then
                if [[ "${2: -1}" != "/" ]]; then
                  local DESTINATION="$2/"
                else
                  local DESTINATION="$2"
                fi
                local HAVE_DESTINATION=true
                shift 2
            else
                help 1
            fi
            ;;
        "-t"|"--target")
            if [ -n "$2" ]
            then
                if [[ "$2" == "manager" ]] || [[ "$2" == "agent" ]] || [[ "$2" == "api" ]]; then
                  local TARGET="$2"
                  local HAVE_TARGET=true
                  shift 2
                else
                  help 1
                fi
            else
                help 1
            fi
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]
            then
                if [[ "$2" == "x86_64" ]] || [[ "$2" == "amd64" ]]; then
                  local ARCHITECTURE="x86_64"
                  local CONTAINER_NAME="${RPM_X86_BUILDER}"
                  local DOCKERFILE_PATH="${RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
                  local HAVE_ARCHITECTURE=true
                elif [[ "$2" == "i386" ]]; then
                  local ARCHITECTURE="i386"
                  local CONTAINER_NAME="${RPM_I386_BUILDER}"
                  local DOCKERFILE_PATH="${RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
                  local HAVE_ARCHITECTURE=true
                else
                  echo "Invalid architecture. Choose: amd64 (x86_64 is accepted too) or i386."
                  help 1
                fi
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--revision")
            if [ -n "$2" ]
            then
                local REVISION="$2"
                local HAVE_REVISION=true
                shift 2
            else
                help 1
            fi
            ;;
        "-l"|"--legacy")
            local LEGACY=true
            shift 1
            ;;
        "-j"|"--jobs")
            if [ -n "$2" ]
            then
                local JOBS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-p"|"--path")
            if [ -n "$2" ]
            then
                local INSTALLATION_PATH="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-d"|"--debug")
            DEBUG="yes"
            shift 1
            ;;
        "-k" | "--checksum")
            CHECKSUM="yes"
            shift 1
            ;;
        *)
            help 1
        esac
    done

    if [[ "$LEGACY" == true ]]; then
      if [[ "$ARCHITECTURE" == "x86_64" ]]; then
        local REVISION="${REVISION}.el5"
        local CONTAINER_NAME="${LEGACY_RPM_X86_BUILDER}"
        local DOCKERFILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
      else
        local REVISION="${REVISION}.el5"
        local CONTAINER_NAME="${LEGACY_RPM_I386_BUILDER}"
        local DOCKERFILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/${ARCHITECTURE}"
      fi
    fi

    if [[ "$HAVE_BRANCH" == true ]] && [[ "$HAVE_DESTINATION" == true ]] && [[ "$HAVE_TARGET" == true ]] && [[ "$HAVE_ARCHITECTURE" == true ]] && [[ "$HAVE_REVISION" == true ]]; then
      if [[ "$TARGET" != "api" ]]; then
        local SOURCE_REPOSITORY="$WAZUH_SOURCE_REPOSITORY"
        # Download the sources
        git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch -vvvv
        local VERSION="$(cat ${SOURCES_DIRECTORY}/src/VERSION | cut -d 'v' -f 2)"
        if [[ "$TARGET" == "manager" ]] && [[ "$LEGACY" = true ]]; then
            local MAJOR_MINOR="$(echo $VERSION | cut -c 2-4)"
            if [[ "${MAJOR_MINOR}" > "3.9" ]] || [[ "${MAJOR_MINOR}" == "3.9" ]]; then
                echo "Wazuh Manager is not supported for CentOS 5 from v3.9.0."
                echo "Version to build: ${VERSION}."
                exit 1
            fi
        fi
      else
         local SOURCE_REPOSITORY="$API_SOURCE_REPOSITORY"
         # Download the sources
         git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch -vvvv
        local VERSION="$(grep version ${SOURCES_DIRECTORY}/package.json | cut -d '"' -f 4)"
      fi

      build_container $TARGET $VERSION $ARCHITECTURE $CONTAINER_NAME $DOCKERFILE_PATH || exit 1
      build_package $TARGET $VERSION $REVISION $ARCHITECTURE $DESTINATION $CONTAINER_NAME $DOCKERFILE_PATH $JOBS $INSTALLATION_PATH $DEBUG $CHECKSUM || exit 1
    else
      echo "ERROR: Need more parameters"
      help 1
    fi


    return 0
}

main "$@"
