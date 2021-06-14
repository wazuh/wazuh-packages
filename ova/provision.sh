#!/bin/bash

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
BRANCH=$5
BRANCHDOC=$6
DEBUG=$7
UI_REVISION=$8
INSTALLER="unattended-installation.sh"
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

# System configuration
systemConfig

curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCHDOC}/resources/open-distro/unattended-installation/${INSTALLER} 

# Edit installation script
preInstall

sh ${INSTALLER}

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

# Edit installation 
postInstall

clean
