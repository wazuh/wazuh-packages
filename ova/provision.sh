#!/bin/bash

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
BRANCH=$5
BRANCHDOC=$6
DEBUG=$7
UI_REVISION=$8
INSTALLER="all-in-one-installation.sh"
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"

# Set debug mode
[[ ${DEBUG} = "yes" ]] && set -exf || set -ef

# Display dev/prod
echo "Using ${PACKAGES_REPOSITORY} packages"

# Load bash functions
. ${CURRENT_PATH}/assets/steps.sh

# System configuration
configSystem

# Download unattended installer
curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCHDOC}/resources/open-distro/unattended-installation/${INSTALLER} 

# Edit installation script
preInstall

# Run unattended installer
sh ${INSTALLER}

# Stop services and enable manager
systemctl stop kibana filebeat elasticsearch wazuh-manager
systemctl enable wazuh-manager

# Edit installation 
postInstall

# Clean system and unnused data
clean
