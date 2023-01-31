#!/bin/bash

# Gets the absolute path of the script, used to load the common.sh file
ABSOLUTE_PATH="$( cd $(dirname ${0}) ; pwd -P )"
. ${ABSOLUTE_PATH}/common.sh

set -x

check_system
download_packages

indexer_installation
echo "Wazuh indexer installation completed."

manager_installation
echo "Wazuh manager installation completed."

filebeat_installation
echo "Filebeat installation completed."

dashboard_installation
echo "Wazuh dashboard installation completed."

