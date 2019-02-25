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
DEB_AMD64_BUILDER="deb_builder_amd64"
DEB_I386_BUILDER="deb_builder_i386"
DEB_AMD64_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/amd64"
DEB_I386_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/i386"
SOURCES_DIRECTORY="${CURRENT_PATH}/repository"
API_SOURCE_REPOSITORY="https://github.com/wazuh/wazuh-api"
WAZUH_SOURCE_REPOSITORY="https://github.com/wazuh/wazuh"
BRAND="wazuh"
PACKAGE_EXTENSION="deb"



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

    # Build the Debian package with a Docker container
    docker run -t --rm -v ${DESTINATION}:/var/local/wazuh \
        -v ${SOURCES_DIRECTORY}:/build_wazuh/${TARGET}/wazuh-${TARGET}-${VERSION} \
        -v ${DOCKERFILE_PATH}/wazuh-${TARGET}:/${TARGET} \
        ${CONTAINER_NAME} ${TARGET} ${VERSION} ${ARCHITECTURE} ${REVISION} ${JOBS} ${INSTALLATION_PATH} || exit 1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.gz,wazuh-*} ${SOURCES_DIRECTORY}

    echo "Package ${BRAND}-${TARGET}_${VERSION}-${REVISION}_${ARCHITECTURE}.${PACKAGE_EXTENSION} added to $DESTINATION."

    return 0
}



function build_container() {
    local TARGET="$1"
    local VERSION="$2"
    local ARCHITECTURE="$3"
    local CONTAINER_NAME="$4"
    local DOCKERFILE_PATH="$5"

    # Copy the necessary files
    cp gen_permissions.sh ${SOURCES_DIRECTORY}
    cp build.sh ${DOCKERFILE_PATH}

    # Copy the "specs" files for the Debian package
    cp -rp SPECS/$VERSION/wazuh-$TARGET ${DOCKERFILE_PATH}/

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}

    return 0
}

function help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. $BRANCH"
    echo "    -d, --destination <path>  [Required] Set the destination path of package."
    echo "    -t, --target <target>     [Required] Target package to build [manager/api/agent]."
    echo "    -a, --architecture <arch> [Required] Target architecture of the package [amd64/i386]."
    echo "    -r, --revision <rev>      [Required] Package revision that append to version e.g. x.x.x-rev"
    echo "    -j, --jobs <number>       [Optional] Number of parallel jobs when compiling."
    echo "    -p, --path <path>         [Optional] Installation path for the package. By default: /var/ossec."
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
    local JOBS="1"                        # Compilation jobs.
    local INSTALLATION_PATH="/var/ossec"  # Path where package will be installed bu default.
    local VERSION=""
    local SOURCE_REPOSITORY=""
    local CONTAINER_NAME=""
    local DOCKERFILE_PATH=""

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
        "-d"|"--destination")
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
                  local ARCHITECTURE="amd64"
                  local CONTAINER_NAME="$DEB_AMD64_BUILDER"
                  local DOCKERFILE_PATH="$DEB_AMD64_BUILDER_DOCKERFILE"
                  local HAVE_ARCHITECTURE=true
                elif [[ "$2" == "i386" ]]; then
                  local ARCHITECTURE="i386"
                  local CONTAINER_NAME="$DEB_I386_BUILDER"
                  local DOCKERFILE_PATH="$DEB_I386_BUILDER_DOCKERFILE"
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
        *)
            help 1
        esac
    done

    if [[ "$HAVE_BRANCH" == true ]] && [[ "$HAVE_DESTINATION" == true ]] && [[ "$HAVE_TARGET" == true ]] && [[ "$HAVE_ARCHITECTURE" == true ]] && [[ "$HAVE_REVISION" == true ]]; then
      if [[ "$TARGET" != "api" ]]; then
        local SOURCE_REPOSITORY="$WAZUH_SOURCE_REPOSITORY"
        # Download the sources
        git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch -vvvv
        local VERSION="$(cat ${SOURCES_DIRECTORY}/src/VERSION | cut -d 'v' -f 2)"
      else
         local SOURCE_REPOSITORY="$API_SOURCE_REPOSITORY"
         # Download the sources
         git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch -vvvv
        local VERSION="$(grep version ${SOURCES_DIRECTORY}/package.json | cut -d '"' -f 4)"
      fi

      build_container $TARGET $VERSION $ARCHITECTURE $CONTAINER_NAME $DOCKERFILE_PATH || exit 1
      build_package $TARGET $VERSION $REVISION $ARCHITECTURE $DESTINATION $CONTAINER_NAME $DOCKERFILE_PATH $JOBS $INSTALLATION_PATH || exit 1
    else
      echo "ERROR: Need more parameters"
      help 1
    fi


    return 0
}

main "$@"
