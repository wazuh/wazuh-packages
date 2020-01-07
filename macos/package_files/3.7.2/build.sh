#!/bin/bash
# Program to build OSX wazuh-agent
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

DESTINATION_PATH=$1
SOURCES_PATH=$2
BUILD_JOBS=$3

function configure() {
    echo USER_LANGUAGE="en" > ${CONFIG}
    echo USER_NO_STOP="y" >> ${CONFIG}
    echo USER_INSTALL_TYPE="agent" >> ${CONFIG}
    echo USER_DIR="${DESTINATION_PATH}" >> ${CONFIG}
    echo USER_DELETE_DIR="y" >> ${CONFIG}
    echo USER_CLEANINSTALL="y" >> ${CONFIG}
    echo USER_BINARYINSTALL="y" >> ${CONFIG}
    echo USER_AGENT_SERVER_IP="MANAGER_IP" >> ${CONFIG}
    echo USER_ENABLE_SYSCHECK="y" >> ${CONFIG}
    echo USER_ENABLE_ROOTCHECK="y" >> ${CONFIG}
    echo USER_ENABLE_OPENSCAP="n" >> ${CONFIG}
    echo USER_ENABLE_CISCAT="n" >> ${CONFIG}
    echo USER_ENABLE_ACTIVE_RESPONSE="y" >> ${CONFIG}
    echo USER_CA_STORE="n" >> ${CONFIG}
}

function build() {

    configure

    make -C ${SOURCES_PATH}/src deps

    echo "Generating Wazuh executables"
    make -j$JOBS -C ${SOURCES_PATH}/src DYLD_FORCE_FLAT_NAMESPACE=1 TARGET=agent PREFIX=${DESTINATION_PATH} build

    # install

    echo "Running install script"
    ${SOURCES_PATH}/install.sh
}

build