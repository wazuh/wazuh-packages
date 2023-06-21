#!/bin/bash

PACKAGES_REPOSITORY=$1
DEBUG=$2

RESOURCES_PATH="/tmp/unattended_installer"
BUILDER="builder.sh"
INSTALLER="wazuh-install.sh"
SYSTEM_USER="wazuh-user"
HOSTNAME="wazuh-server"

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
BUILDER_ARGS="-i"
INSTALL_ARGS="-a"

if [[ "${PACKAGES_REPOSITORY}" == "dev" ]]; then
  BUILDER_ARGS+=" -d"
elif [[ "${PACKAGES_REPOSITORY}" == "staging" ]]; then
  BUILDER_ARGS+=" -d staging"
fi

if [[ "${DEBUG}" = "yes" ]]; then
  INSTALL_ARGS+=" -v"
fi

echo "Using ${PACKAGES_REPOSITORY} packages"

. ${ASSETS_PATH}/steps.sh

# Build install script
bash ${RESOURCES_PATH}/${BUILDER} ${BUILDER_ARGS}
WAZUH_VERSION=$(cat ${RESOURCES_PATH}/${INSTALLER} | grep "wazuh_version=" | cut -d "\"" -f 2)

# System configuration
systemConfig

# Edit installation script
preInstall

# Install
bash ${RESOURCES_PATH}/${INSTALLER} ${INSTALL_ARGS}

systemctl stop wazuh-dashboard filebeat wazuh-indexer wazuh-manager
systemctl enable wazuh-manager
rm -f /var/log/wazuh-indexer/*
rm -f /var/log/filebeat/*

clean
