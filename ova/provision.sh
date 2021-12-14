#!/bin/bash

PACKAGES_REPOSITORY=$1
DEBUG=$2

RESOURCES_PATH="/tmp/unattended_scripts"
UNATTENDED_PATH="${RESOURCES_PATH}/open-distro/unattended-installation"
INSTALLER="unattended-installation.sh"
WAZUH_VERSION=$(cat ${UNATTENDED_PATH}/${INSTALLER} | grep "WAZUH_VER=" | cut -d "\"" -f 2)

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

# System configuration
systemConfig

# Edit installation script
preInstall

sh ${UNATTENDED_PATH}/${INSTALLER}

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

clean
