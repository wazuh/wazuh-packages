#!/bin/bash

# Wazuh package builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
# Script parameters to build the package
TARGET="wazuh-dashboard"
ARCHITECTURE=$1
REVISION=$2
FUTURE=$3
BASE_LOCATION=$4
REFERENCE=$5
DIRECTORY_BASE="/usr/share/wazuh-dashboard"

if [ "${FUTURE}" = "yes" ];then
    VERSION="99.99.0"
else
    if [ "${REFERENCE}" ];then
        VERSION=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${REFERENCE}/VERSION | cat)
    else
        VERSION=$(cat /root/VERSION)
    fi
fi

# Build directories
BUILD_DIR=/build
RPM_BUILD_DIR=${BUILD_DIR}/rpmbuild
FILE_NAME="${TARGET}-${VERSION}-${REVISION}"
PKG_PATH="${RPM_BUILD_DIR}/RPMS/${ARCHITECTURE}"
RPM_FILE="${FILE_NAME}.${ARCHITECTURE}.rpm"
mkdir -p ${RPM_BUILD_DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the sources directory to build the source tar.gz
PKG_NAME=${TARGET}-${VERSION}
mkdir ${BUILD_DIR}/${PKG_NAME}


# Including spec file
if [ "${REFERENCE}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${REFERENCE} | tar zx
    cp ./wazuh*/stack/dashboard/rpm/${TARGET}.spec ${RPM_BUILD_DIR}/SPECS/${PKG_NAME}.spec
    cp -r ./wazuh*/* /root/
else
    cp /root/stack/dashboard/rpm/${TARGET}.spec ${RPM_BUILD_DIR}/SPECS/${PKG_NAME}.spec
fi


# Generating source tar.gz
cd ${BUILD_DIR} && tar czf "${RPM_BUILD_DIR}/SOURCES/${PKG_NAME}.tar.gz" "${PKG_NAME}"

# Building RPM
/usr/bin/rpmbuild --define "_topdir ${RPM_BUILD_DIR}" --define "_version ${VERSION}" \
    --define "_release ${REVISION}" --define "_localstatedir ${DIRECTORY_BASE}" \
    --define "_base ${BASE_LOCATION}" \
    --target ${ARCHITECTURE} -ba ${RPM_BUILD_DIR}/SPECS/${PKG_NAME}.spec

cd ${PKG_PATH} && sha512sum ${RPM_FILE} > /tmp/${RPM_FILE}.sha512

find ${PKG_PATH}/ -maxdepth 3 -type f -name "${FILE_NAME}*" -exec mv {} /tmp/ \;
