#!/bin/bash

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="x86_64"
LEGACY="no"
OUTDIR="${HOME}/unstable/futures/yum/"
BRANCH="master"
RELEASE="1"
TARGET=""
TARGET_VERSION=""
JOBS="4"
RPM_X86_BUILDER="rpm_builder_x86"
RPM_I386_BUILDER="rpm_builder_i386"
RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/6"
LEGACY_RPM_X86_BUILDER="rpm_legacy_builder_x86"
LEGACY_RPM_I386_BUILDER="rpm_legacy_builder_i386"
LEGACY_RPM_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/5"
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

build_rpm() {
    CONTAINER_NAME="$1"
    DOCKERFILE_PATH="$2"
    VERSION="$3"

    SOURCES_DIRECTORY="/tmp/wazuh-builder/sources-$(( ( RANDOM % 1000000 )  + 1 ))" 

    # Download the sources
    git clone ${SOURCE_REPOSITORY} -b $BRANCH ${SOURCES_DIRECTORY} --depth=1 --single-branch
    
    # Copy the necessary files
    cp build.sh ${DOCKERFILE_PATH}

    if [[ "$TARGET" != "api" ]]; then
        CURRENT_VERSION=$(cat ${SOURCES_DIRECTORY}/src/VERSION | cut -d 'v' -f 2)
    else
        CURRENT_VERSION=$(grep version ${SOURCES_DIRECTORY}/package.json | cut -d '"' -f 4)
    fi

    if [[ "$CURRENT_VERSION" != "$VERSION" ]] ; then
      SHORT_CURRENT_VERSION=$(echo $CURRENT_VERSION | cut -d'.' -f 1,2)
      echo "Current version -> $CURRENT_VERSION"
      echo "Short current version -> $SHORT_CURRENT_VERSION"
      echo "Target version -> $VERSION"
      echo "v$VERSION" >  ${SOURCES_DIRECTORY}/src/VERSION
      cp -rp SPECS/$CURRENT_VERSION SPECS/$VERSION
      mv SPECS/$VERSION/wazuh-manager-$CURRENT_VERSION.spec SPECS/$VERSION/wazuh-manager-$VERSION.spec
      mv SPECS/$VERSION/wazuh-agent-$CURRENT_VERSION.spec SPECS/$VERSION/wazuh-agent-$VERSION.spec
      mv SPECS/$VERSION/wazuh-api-$CURRENT_VERSION.spec SPECS/$VERSION/wazuh-api-$VERSION.spec

      sed -i "s|${CURRENT_VERSION}|${VERSION}|" SPECS/$VERSION/wazuh-manager-$VERSION.spec
      sed -i "s|make deps RESOURCE.*|make deps RESOURCES_URL=http://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-manager-$VERSION.spec
      sed -i "0,/make deps/s||make deps RESOURCES_URL=https://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-manager-$VERSION.spec

      sed -i "s|${CURRENT_VERSION}|${VERSION}|" SPECS/$VERSION/wazuh-agent-$VERSION.spec
      sed -i "s|make deps RESOURCE.*|make deps RESOURCES_URL=http://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-agent-$VERSION.spec
      sed -i "0,/make deps/s||make deps RESOURCES_URL=https://packages.wazuh.com/deps/${SHORT_CURRENT_VERSION}|" SPECS/$VERSION/wazuh-agent-$VERSION.spec

      sed -i "s|${CURRENT_VERSION}|${VERSION}|" SPECS/$VERSION/wazuh-api-$VERSION.spec
    fi
    
    cp SPECS/$VERSION/wazuh-$TARGET-$VERSION.spec ${DOCKERFILE_PATH}/wazuh.spec

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
        build_rpm ${RPM_X86_BUILDER} ${RPM_BUILDER_DOCKERFILE}/x86_64 ${TARGET_VERSION} || exit 1

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
        build_rpm ${BUILD_NAME} ${FILE_PATH} ${TARGET_VERSION}|| exit 1
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
    echo "    -v, --version <version>   Define target version to build."
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
