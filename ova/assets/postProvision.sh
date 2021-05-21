#!/bin/bash

DEBUG=$1
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"

# Stop services after reload
systemctl stop wazuh-manager elasticsearch filebeat kibana

# Remove everything related to vagrant
mv ${CUSTOM_PATH}/removeVagrant.service /etc/systemd/system/
mv ${CUSTOM_PATH}/removeVagrant.sh /home/wazuh/
chmod 755 /home/wazuh/removeVagrant.sh
systemctl daemon-reload
systemctl enable removeVagrant.service

# Clear synced files
rm -rf ${CURRENT_PATH}/* ${CURRENT_PATH}/.gitignore

# Remove logs
find /var/log/ -type f -exec sh -c ': > "$1"' - {} \;
find /var/ossec/logs/ -type f -exec sh -c ': > "$1"' - {} \;

# Clean history
history -c

# Apply cleaning changes
shutdown -r now > /dev/null 2>&1
