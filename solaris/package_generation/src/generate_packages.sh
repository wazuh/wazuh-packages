#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2019 Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# This script need packages generation scripts to be on the Solaris machine.

######### GLOBAL VARIABLES #################################################

BUILD_PATH="/export/home/vagrant/build" # cloning in the shared folder is too slow
PACKAGE_GENERATION_SCRIPTS_PATH="/tmp/shared/${SOL_PATH}" # this will be changed when we start using Jekins.

############################################################################

if [ ! -d "${BUILD_PATH}" ]
then
    echo "Creating building directory at ${BUILD_PATH}"
    mkdir -p ${BUILD_PATH}
fi

echo "Entering build directory"
cd ${BUILD_PATH}

echo "Coping files from shared folder"
cp -r /tmp/shared/${SOLARIS_VERSION} .
chmod +x ${SOLARIS_VERSION}/*.sh


cd ${SOLARIS_VERSION}

echo "downloading wazuh source"
./generate_wazuh_packages.sh -d ${BRANCH_TAG}

echo "Generating Wazuh package"
./generate_wazuh_packages.sh -b ${BRANCH_TAG}

package_filename="wazuh-agent_$VERSION-sol10-i386.pkg"

if [[ ${SOLARIS_VERSION} == "solaris11" ]]
then
    package_filename="wazuh-agent_$VERSION-sol11-i386.p5p"
fi

if [ "${CHECKSUM}" == "yes" ]; then
    ./generate_wazuh_packages.sh -k
    cp "${package_filename}.sha512" /tmp/shared
fi

VERSION=`cat ${BUILD_PATH}/$SOLARIS_VERSION/wazuh/src/VERSION`

echo "Coping package to shared folder"

cp "$package_filename" /tmp/shared

exit 0
