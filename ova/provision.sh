#!/bin/bash


PACKAGES_REPOSITORY=$1
DEBUG=$2
PACKAGES_BRANCH=$3

INSTALLER="unattended-installation.sh"
URL_INSTALLER="https://raw.githubusercontent.com/wazuh/wazuh-packages/${PACKAGES_BRANCH}/resources/open-distro/unattended-installation"
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

echo "Using ${PACKAGES_REPOSITORY} packages"

curl -so ${INSTALLER} ${URL_INSTALLER}/${INSTALLER}
WAZUH_VERSION=$(cat ${INSTALLER} | grep "WAZUH_VER=" | cut -d "\"" -f 2)

. ${ASSETS_PATH}/steps.sh

# System configuration
systemConfig

# Edit installation script
preInstall

sh ${INSTALLER}

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

# Edit installation 
postInstall

clean
