#!/bin/bash

# Wazuh indexer builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
TARGET="wazuh-indexer"
ARCHITECTURE=$1
REVISION=$2
FUTURE=$3
BASE_LOCATION=$4
REFERENCE=$5
DIRECTORY_BASE="/usr/share/wazuh-indexer"

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
PKG_NAME="${TARGET}-${VERSION}"
PKG_PATH="${BUILD_DIR}/${TARGET}"
SOURCER_DIR="${PKG_PATH}/${PKG_NAME}"

mkdir -p ${SOURCER_DIR}/debian

# Including spec file
if [ "${REFERENCE}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${REFERENCE} | tar zx
    cp -r ./wazuh*/stack/indexer/deb/debian/* ${SOURCER_DIR}/debian/
    cp -r ./wazuh*/* /root/
else
    cp -r /root/stack/indexer/deb/debian/* ${SOURCER_DIR}/debian/
fi

# Generating directory structure to build the .deb package
cd ${BUILD_DIR}/${TARGET} && tar -czf ${PKG_NAME}.orig.tar.gz "${PKG_NAME}"

# Configure the package with the different parameters
sed -i "s:VERSION:${VERSION}:g" ${SOURCER_DIR}/debian/changelog
sed -i "s:RELEASE:${REVISION}:g" ${SOURCER_DIR}/debian/changelog

# Installing build dependencies
cd ${SOURCER_DIR}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild --no-lintian -eINSTALLATION_DIR="${DIRECTORY_BASE}" -eBASE="${BASE_LOCATION}" -eBASE_VERSION="${VERSION}" -eBASE_REVISION="${REVISION}" -b -uc -us

DEB_FILE="${TARGET}_${VERSION}-${REVISION}_${ARCHITECTURE}.deb"

cd ${PKG_PATH} && sha512sum ${DEB_FILE} > /tmp/${DEB_FILE}.sha512

mv ${PKG_PATH}/${DEB_FILE} /tmp/
