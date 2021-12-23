#!/bin/bash

PACKAGES_REPOSITORY=$1
DEBUG=$2

RESOURCES_PATH="/tmp/unattended_scripts"
INSTALLER="wazuh_install.sh"
WAZUH_VERSION=$(cat ${RESOURCES_PATH}/${INSTALLER} | grep "wazuh_version=" | cut -d "\"" -f 2)
SYSTEM_USER="wazuh-user"
HOSTNAME="wazuh-manager"

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
BASH_ARGS="-a -l -v"


if [[ ${DEBUG} = "yes" ]]; then
  set -ex 
  BASH_ARGS+=" -d"
else
  set -e
fi

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

# System configuration
systemConfig

# Edit installation script
preInstall

bash ${RESOURCES_PATH}/${INSTALLER} ${BASH_ARGS}

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

clean
