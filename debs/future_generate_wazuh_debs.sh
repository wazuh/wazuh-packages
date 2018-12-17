#!/bin/bash

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="amd64"
OUTDIR="${HOME}/futures/apt/"
BRANCH="master"
REVISION="1"
TARGET=""
TARGET_VERSION=""
JOBS="4"
INSTALLATION_PATH="/var/ossec"
DEB_AMD64_BUILDER="deb_builder_amd64"
DEB_I386_BUILDER="deb_builder_i386"
DEB_AMD64_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/amd64"
DEB_I386_BUILDER_DOCKERFILE="${CURRENT_PATH}/Debian/i386"

if [ -z "$OUTDIR" ]
then
    if [ -n "$DEB_OUTDIR" ]
    then
        OUTDIR=$DEB_OUTDIR
    else
        echo "ERROR: \$DEB_OUTDIR was not defined."
        echo "Tip: echo export DEB_OUTDIR=\"/my/output/dir\" >> ~/.bash_profile"
        return 1
    fi
fi

build_deb() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"
    VERSION="$3"

    SOURCES_DIRECTORY="/tmp/wazuh-builder/sources-$(( ( RANDOM % 1000 )  + 1 ))"

    # Download the sources
    git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch
    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}
    cp gen_permissions.sh ${SOURCES_DIRECTORY}

    if [[ "$TARGET" != "api" ]]; then
        # Review " in this command
        CURRENT_VERSION=$(cat ${SOURCES_DIRECTORY}/src/VERSION | cut -d 'v' -f 2)
        echo "v$VERSION" >  ${SOURCES_DIRECTORY}/src/VERSION || exit 1
        sed -i "s|v${CURRENT_VERSION}|v${VERSION}|g" ${SOURCES_DIRECTORY}/src/update/ruleset/RULESET_VERSION || exit 1
    else
        # Review " in this command
        CURRENT_VERSION=$(grep version ${SOURCES_DIRECTORY}/package.json | cut -d '"' -f 4)
        sed -i "s|${CURRENT_VERSION}|${VERSION}|" ${SOURCES_DIRECTORY}/package.json || exit 1
    fi
    
    if [[ "$CURRENT_VERSION" != "$VERSION" ]] ; then
      SHORT_CURRENT_VERSION=$(echo $CURRENT_VERSION | cut -d'.' -f 1,2)
      SHORT_VERSION=$(echo $VERSION | cut -d'.' -f 1,2)
      echo "Current version -> $CURRENT_VERSION"
      echo "Short current version -> $SHORT_CURRENT_VERSION"
      echo "Target version -> $VERSION"
      
      cp -rp SPECS/$CURRENT_VERSION SPECS/$VERSION
      sed -i "1s|^| -- Wazuh, Inc <info@wazuh.com> Fri, 9 Sep 2018 11:00:00 +0000\n\n|" SPECS/$VERSION/wazuh-manager/debian/changelog
      sed -i "1s|^|  * More info: https://documentation.wazuh.com/current/release-notes/\n\n|" SPECS/$VERSION/wazuh-manager/debian/changelog
      sed -i "1s|^|wazuh-manager (${VERSION}-RELEASE) stable; urgency=low\n\n|" SPECS/$VERSION/wazuh-manager/debian/changelog
      sed -i "s|make -C src deps|make -C src deps RESOURCES_URL=https://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-manager/debian/rules

      sed -i "1s|^| -- Wazuh, Inc <info@wazuh.com> Fri, 9 Sep 2018 11:00:00 +0000\n\n|" SPECS/$VERSION/wazuh-agent/debian/changelog
      sed -i "1s|^|  * More info: https://documentation.wazuh.com/current/release-notes/\n\n|" SPECS/$VERSION/wazuh-agent/debian/changelog
      sed -i "1s|^|wazuh-agent (${VERSION}-RELEASE) stable; urgency=low\n\n|" SPECS/$VERSION/wazuh-agent/debian/changelog
      sed -i "s|make -C src deps|make -C src deps RESOURCES_URL=https://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-agent/debian/rules

      sed -i "1s|^| -- Wazuh, Inc <info@wazuh.com> Fri, 9 Sep 2018 11:00:00 +0000\n\n|" SPECS/$VERSION/wazuh-api/debian/changelog
      sed -i "1s|^|  * More info: https://documentation.wazuh.com/current/release-notes/\n\n|" SPECS/$VERSION/wazuh-api/debian/changelog
      sed -i "1s|^|wazuh-api (${VERSION}-RELEASE) stable; urgency=low\n\n|" SPECS/$VERSION/wazuh-api/debian/changelog

      sed -i "s|${CURRENT_VERSION}|${VERSION}|g" SPECS/$VERSION/wazuh-api/debian/control
      sed -i "s|${SHORT_CURRENT_VERSION}|${SHORT_VERSION}|g" SPECS/$VERSION/wazuh-api/debian/control
    fi

    # Copy the "specs" files for the Debian package
    cp -rp SPECS/$VERSION/wazuh-$TARGET ${DOCKERFILE_PATH}/

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}

    # Build the Debian package with a Docker container
    docker run -t --rm -v $OUTDIR:/var/local/wazuh \
        -v ${SOURCES_DIRECTORY}:/build_wazuh/$TARGET/wazuh-$TARGET-$VERSION \
        -v ${DOCKERFILE_PATH}/wazuh-$TARGET:/$TARGET \
        ${CONTAINER_NAME} $TARGET $VERSION $ARCHITECTURE $REVISION $JOBS $INSTALLATION_PATH || exit 1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.gz,wazuh-*} ${SOURCES_DIRECTORY}

    echo "Package $(ls $OUTDIR -Art | tail -n 1) added to $OUTDIR."

    return 0
}

build() {

    if [[ "$TARGET" = "api" ]]; then

        SOURCE_REPOSITORY="https://github.com/wazuh/wazuh-api"
        build_deb ${DEB_AMD64_BUILDER} ${DEB_AMD64_BUILDER_DOCKERFILE} ${TARGET_VERSION} || exit 1

    elif [[ "$TARGET" = "manager" ]] || [[ "$TARGET" = "agent" ]]; then

        SOURCE_REPOSITORY="https://github.com/wazuh/wazuh"
        BUILD_NAME=""
        FILE_PATH=""
        if [[ "$ARCHITECTURE" = "x86_64" ]] || [[ "$ARCHITECTURE" = "amd64" ]]; then
            ARCHITECTURE="amd64"
            BUILD_NAME="${DEB_AMD64_BUILDER}"
            FILE_PATH="${DEB_AMD64_BUILDER_DOCKERFILE}"
        elif [[ "$ARCHITECTURE" = "i386" ]]; then
            BUILD_NAME="${DEB_I386_BUILDER}"
            FILE_PATH="${DEB_I386_BUILDER_DOCKERFILE}"
        else
            echo "Invalid architecture. Choose: x86_64 (amd64 is accepted too) or i386."
            exit 1
        fi
        build_deb ${BUILD_NAME} ${FILE_PATH} ${TARGET_VERSION} || exit 1
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
    echo "    -b, --branch <branch>     Select Git branch or tag [$BRANCH]."
    echo "    -v, --version <version>   Define target version to build."
    echo "    -h, --help                Show this help."
    echo "    -t, --target              Target package to build: manager, api or agent."
    echo "    -a, --architecture        Target architecture of the package."
    echo "    -j, --jobs                Change number of parallel jobs when compiling the manager or agent."
    echo "    -r, --revision            Package revision."
    echo "    -p, --path                Installation path for the package. By default: /var/ossec."
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
                shift 2
            else
                help 1
            fi
            ;;
        "-v"|"--version")
            if [ -n "$2" ]
            then
                TARGET_VERSION="$2"
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
        "-r"|"--revision")
            if [ -n "$2" ]
            then
                REVISION="$2"
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
