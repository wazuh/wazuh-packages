#!/bin/bash
# Program to build OSX wazuh-agent
# Wazuh package generator
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
set -exf
DESTINATION_PATH=$1
SOURCES_PATH=$2
BUILD_JOBS=$3
INSTALLATION_SCRIPTS_DIR=${DESTINATION_PATH}/packages_files/agent_installation_scripts

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

    echo "Running install script"
    ${SOURCES_PATH}/install.sh

    find ${DESTINATION_PATH}/ruleset/sca/ -type f -exec rm -f {} \;

    # Add the auxiliar script used while installing the package
    mkdir -p ${INSTALLATION_SCRIPTS_DIR}/
    cp ${SOURCES_PATH}/gen_ossec.sh ${INSTALLATION_SCRIPTS_DIR}/
    cp ${SOURCES_PATH}/add_localfiles.sh ${INSTALLATION_SCRIPTS_DIR}/

    mkdir -p ${INSTALLATION_SCRIPTS_DIR}/src/init
    mkdir -p ${INSTALLATION_SCRIPTS_DIR}/etc/templates/config/{generic,darwin}

    cp -r ${SOURCES_PATH}/etc/templates/config/generic ${INSTALLATION_SCRIPTS_DIR}/etc/templates/config
    cp -r ${SOURCES_PATH}/etc/templates/config/darwin ${INSTALLATION_SCRIPTS_DIR}/etc/templates/config

    find ${SOURCES_PATH}/src/init/ -name *.sh -type f -exec install -m 0640 {} ${INSTALLATION_SCRIPTS_DIR}/src/init \;

    mkdir -p ${INSTALLATION_SCRIPTS_DIR}/sca/generic
    mkdir -p ${INSTALLATION_SCRIPTS_DIR}/sca/darwin/{15,16,17,18}

    cp -r ${SOURCES_PATH}/etc/sca/darwin ${INSTALLATION_SCRIPTS_DIR}/sca
    cp -r ${SOURCES_PATH}/etc/sca/generic ${INSTALLATION_SCRIPTS_DIR}/sca
    cp ${SOURCES_PATH}/etc/templates/config/generic/sca.files ${INSTALLATION_SCRIPTS_DIR}/sca/generic/
    cp ${SOURCES_PATH}/etc/templates/config/darwin/15/sca.files ${INSTALLATION_SCRIPTS_DIR}/sca/darwin/15/
    cp ${SOURCES_PATH}/etc/templates/config/darwin/16/sca.files ${INSTALLATION_SCRIPTS_DIR}/sca/darwin/16/
    cp ${SOURCES_PATH}/etc/templates/config/darwin/17/sca.files ${INSTALLATION_SCRIPTS_DIR}/sca/darwin/17/
    cp ${SOURCES_PATH}/etc/templates/config/darwin/18/sca.files ${INSTALLATION_SCRIPTS_DIR}/sca/darwin/18/

    cp ${SOURCES_PATH}/src/VERSION ${INSTALLATION_SCRIPTS_DIR}/src/
    cp ${SOURCES_PATH}/src/REVISION ${INSTALLATION_SCRIPTS_DIR}/src/
    cp ${SOURCES_PATH}/src/LOCATION ${INSTALLATION_SCRIPTS_DIR}/src/
}

build