#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="x86_64"
LEGACY="no"
OUTDIR="${HOME}/3.x/yum-dev/"
BRANCH="master"
RELEASE="1"
TARGET=""
JOBS="4"
RPM_X86_BUILDER="rpm_builder_x86"
RPM_I386_BUILDER="rpm_builder_i386"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/6"
LEGACY_RPM_X86_BUILDER="rpm_legacy_builder_x86"
LEGACY_RPM_I386_BUILDER="rpm_legacy_builder_i386"
LEGACY_RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/5"
LEGACY_TAR_FILE="${LEGACY_RPM_BUILDER_DOCKERFILE}/i386/centos-5-i386.tar.gz"
TAR_URL="https://packages-dev.wazuh.com/utils/centos-5-i386-build/centos-5-i386.tar.gz"
INSTALLATION_PATH="/var"

if [ -z "$OUTDIR" ]
then
    if [ -n "$RPM_OUTDIR" ]
    then
        OUTDIR=$RPM_OUTDIR
    else
        echo "ERROR: \$RPM_OUTDIR was not defined."
        echo "Tip: echo export RPM_OUTDIR=\"/my/output/dir\" >> ~/.bash_profile"
        return 1
    fi
fi

if command -v curl > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="curl ${TAR_URL} -o ${LEGACY_TAR_FILE} -s"
elif command -v wget > /dev/null 2>&1 ; then
    DOWNLOAD_TAR="wget ${TAR_URL} -o ${LEGACY_TAR_FILE} -q"
fi

build_rpm() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"

    SOURCES_DIRECTORY="/tmp/wazuh-builder/sources-$(( ( RANDOM % 1000000 )  + 1 ))"

    # Download the sources
    git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch -q

    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    if [[ "$TARGET" != "api" ]]; then
        VERSION="$(cat ${SOURCES_DIRECTORY}/src/VERSION | cut -d 'v' -f 2)"

        if [[ "$TARGET" == "manager" ]] && [[ "$LEGACY" = "yes" ]]; then
            MAJOR_MINOR="$(echo $VERSION | cut -c 2-4)"
            if [[ "${MAJOR_MINOR}" > "3.9" ]] || [[ "${MAJOR_MINOR}" == "3.9" ]]; then
                echo "Wazuh Manager is not supported for CentOS 5 from v3.9.0."
                echo "Version to build: ${VERSION}."
                exit 1
            fi
        fi
    else
        VERSION="$(grep version ${SOURCES_DIRECTORY}/package.json | cut -d '"' -f 4)"
    fi

    cp SPECS/$VERSION/wazuh-$TARGET-$VERSION.spec ${DOCKERFILE_PATH}/wazuh.spec

    # Download the legacy tar file if it is needed
    if [ "${CONTAINER_NAME}" == "${LEGACY_RPM_I386_BUILDER}" ] && [ ! -f "${LEGACY_TAR_FILE}" ]; then
        ${DOWNLOAD_TAR}
    fi
    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}

    # Build the RPM package with a Docker container
    docker run -t --rm -v $OUTDIR:/var/local/wazuh \
        -v ${SOURCES_DIRECTORY}:/build_wazuh/wazuh-$TARGET-$VERSION \
        ${CONTAINER_NAME} $TARGET $VERSION $ARCHITECTURE \
        $JOBS $RELEASE ${INSTALLATION_PATH} || exit 1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.spec} ${SOURCES_DIRECTORY}

    echo "Package $(ls $OUTDIR -Art | tail -n 1) added to $OUTDIR."

    return 0
}

build() {

    if [[ "$TARGET" = "api" ]]; then

        SOURCE_REPOSITORY="https://github.com/wazuh/wazuh-api"
        build_rpm ${RPM_X86_BUILDER} ${RPM_BUILDER_DOCKERFILE}/x86_64 || exit 1

    elif [[ "$TARGET" = "manager" ]] || [[ "$TARGET" = "agent" ]]; then

        SOURCE_REPOSITORY="https://github.com/wazuh/wazuh"
        BUILD_NAME=""
        FILE_PATH=""
        if [[ "$LEGACY" = "yes" ]] && [[ "$ARCHITECTURE" = "x86_64" ]]; then
            OUTDIR="$OUTDIR/5/x86_64"
            RELEASE="$RELEASE.el5"
            BUILD_NAME="${LEGACY_RPM_X86_BUILDER}"
            FILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/$ARCHITECTURE"
        elif [[ "$LEGACY" = "yes" ]] && [[ "$ARCHITECTURE" = "i386" ]]; then
            OUTDIR="$OUTDIR/5/i386"
            RELEASE="$RELEASE.el5"
            BUILD_NAME="${LEGACY_RPM_I386_BUILDER}"
            FILE_PATH="${LEGACY_RPM_BUILDER_DOCKERFILE}/$ARCHITECTURE"
        elif [[ "$LEGACY" = "no" ]] && [[ "$ARCHITECTURE" = "x86_64" ]]; then
            BUILD_NAME="${RPM_X86_BUILDER}"
            FILE_PATH="${RPM_BUILDER_DOCKERFILE}/$ARCHITECTURE"
        else
            BUILD_NAME="${RPM_I386_BUILDER}"
            FILE_PATH="${RPM_BUILDER_DOCKERFILE}/$ARCHITECTURE"
        fi
        build_rpm ${BUILD_NAME} ${FILE_PATH}|| exit 1
    else
        echo "Invalid target. Choose: manager, agent or api."
        exit 1
    fi

    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     Select Git branch [$BRANCH]."
    echo "    -h, --help                Show this help."
    echo "    -t, --target              Target package to build: manager, api or agent."
    echo "    -a, --architecture        Target architecture of the package."
    echo "    -j, --jobs                Change number of parallel jobs when compiling the manager or agent."
    echo "    -l, --legacy              Build the package for CentOS 5."
    echo "    -r, --release             Package release."
    echo "    -p, --path                Installation path for the package. By default: /var."
    echo
    exit $1
}


main() {
    BUILD="no"
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]
            then
                BRANCH="$(echo $2 | cut -d'/' -f2)"
                BUILD="yes"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-t"|"--target")
            if [ -n "$2" ]
            then
                TARGET="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]
            then
                ARCHITECTURE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "$2" ]
            then
                JOBS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--release")
            if [ -n "$2" ]
            then
                RELEASE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-p"|"--path")
            if [ -n "$2" ]
            then
                INSTALLATION_PATH="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-l"|"--legacy")
            LEGACY="yes"
            shift 1
            ;;
        *)
            help 1
        esac
    done

    if [[ "$BUILD" != "no" ]]; then
        build || exit 1
    fi


    return 0
}

main "$@"
