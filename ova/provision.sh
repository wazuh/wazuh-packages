#!/bin/bash


PACKAGES_REPOSITORY=$1
DEBUG=$2
WAZUH_MAJOR=$3

INSTALLER="unattended-installation.sh"
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

# System configuration
systemConfig

if [ "${PACKAGES_REPOSITORY}" = "dev" ]; then
    AWS_SUFFIX="-dev"
fi
curl -so ${INSTALLER} https://packages${AWS_SUFFIX}.wazuh.com/resources/${WAZUH_MAJOR}/open-distro/unattended-installation/unattended-installation.sh

# Edit installation script
preInstall

sh ${INSTALLER}

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

# Edit installation 
postInstall

clean
