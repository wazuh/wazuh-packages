#!/bin/bash

DIRECTORY="wazuh"
REPOSITORY="https://github.com/wazuh/wazuh.git"
BRANCH=$1
JOBS=$2
OUT_NAME=$3
CHECKSUM=$4
PKG_NAME=$5
HAVE_PKG_NAME=false
if [ -n $5 ]
then
    HAVE_PKG_NAME=true
fi


WPKCERT="/etc/wazuh/wpkcert.pem"
WPKEY="/etc/wazuh/wpkcert.key"
OUTDIR="/var/local/wazuh"
CHECKSUMDIR="/var/local/checksum"

main() {

    NO_COMPILE=false
    # Get Wazuh
    git clone $REPOSITORY $DIRECTORY || exit 1
    cd $DIRECTORY
    git checkout $BRANCH

    # Get info
    . src/init/dist-detect.sh
    VERSION=$(cat src/VERSION)
    SHORT_VERSION=$(cat src/VERSION | cut -dv -f2)
    ARCH=$(uname -m)

    # Create package
    if [ -z "$OUTPUT" ]
    then
        if [ "$DIST_NAME" = "centos" ]
        then
            BUILD_TARGET="agent"
            NO_COMPILE=false
        else
            BUILD_TARGET="winagent"
            NO_COMPILE=true
        fi
        OUTPUT="${OUTDIR}/${OUT_NAME}"

        mkdir -p $OUTDIR
    fi

    WAZUH_VERSION=$(cat src/VERSION)
    MAJOR=$(echo ${WAZUH_VERSION} | cut -dv -f2 | cut -d. -f1)
    MINOR=$(echo ${WAZUH_VERSION} | cut -d. -f2)

    if [ "${NO_COMPILE}" == false ]; then
      # Execute gmake deps if the version is greater or equal to 3.5
      if [ $MAJOR -ge 3 ] && [ $MINOR -ge 5 ]; then
          make -C src deps
      fi

      # Compile agent
      make -C src -j $JOBS TARGET=${BUILD_TARGET} || exit 1
      # Clean unuseful files
      clean
      # Preload vars for installer
      preload
    fi

    # Compress and sign package
    if [ "${DIST_NAME}" = "centos" ]; then
        wpkpack $OUTPUT $WPKCERT $WPKEY *
    else

      if [ "${HAVE_PKG_NAME}" == true ]; then
          echo "wpkpack $OUTPUT $WPKCERT $WPKEY ${PKG_NAME} upgrade.bat do_upgrade.ps1"
          cd ${OUTDIR}
          cp /$DIRECTORY/src/win32/{upgrade.bat,do_upgrade.ps1} .
          cp /var/pkg/${PKG_NAME} ${OUTDIR}
          wpkpack $OUTPUT $WPKCERT $WPKEY ${PKG_NAME} upgrade.bat do_upgrade.ps1
          rm -f upgrade.bat do_upgrade.ps1 ${PKG_NAME}
      else
          echo "ERROR: MSI package is needed to build the Windows WPK"
      fi
    fi
    echo "PACKED FILE -> $OUTPUT"
    # Update versions file
    cd ${OUTDIR}
    gen_versions ${OUTPUT} ${SHORT_VERSION}
    if [[ ${CHECKSUM} == "yes" ]]; then
        mkdir -p ${CHECKSUMDIR}
        sha512sum "${OUT_NAME}" > "${CHECKSUMDIR}/${OUT_NAME}.sha512"
    fi
}

clean() {
    rm -rf doc wodles/oscap/content/* gen_ossec.sh add_localfiles.sh Jenkinsfile*
    rm -rf src/{addagent,analysisd,client-agent,config,error_messages,external/*,headers,logcollector,monitord,os_auth,os_crypto,os_csyslogd,os_dbdos_execd}
    rm -rf src/{os_integrator,os_maild,os_netos_regex,os_xml,os_zlib,remoted,reportd,shared,syscheckd,tests,update,wazuh_db,wazuh_modules}

    if [[ "${BUILD_TARGET}" != "winagent" ]]; then
        rm -rf src/win32
    fi

    rm -rf src/*.a
    rm -rf etc/{decoders,lists,rules}

    find etc/templates/config -not -name "sca.files" -delete 2>/dev/null
    find etc/templates/* -maxdepth 0 -not -name "en" -not -name "config" | xargs rm -rf
}

preload() {
    echo 'USER_UPDATE="y"' > etc/preloaded-vars.conf
    echo 'USER_LANGUAGE="en"' >> etc/preloaded-vars.conf
    echo 'USER_NO_STOP="y"' >> etc/preloaded-vars.conf
    echo 'USER_BINARYINSTALL="y"'>> etc/preloaded-vars.conf
    if [[ "${BUILD_TARGET}" != "winagent" ]]; then
        echo 'USER_INSTALL_TYPE="agent"' >> etc/preloaded-vars.conf
    else
        echo 'USER_INSTALL_TYPE="winagent"' >> etc/preloaded-vars.conf
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]
then
    main "$@"
fi
