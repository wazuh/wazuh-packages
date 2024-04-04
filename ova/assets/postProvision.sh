#!/bin/bash

DEBUG=$1
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
SYSTEM_USER="wazuh-user"

# Remove everything related to vagrant
# mv ${CUSTOM_PATH}/removeVagrant.service /etc/systemd/system/
# sed -i "s/USER/${SYSTEM_USER}/g" /etc/systemd/system/removeVagrant.service
# mv ${CUSTOM_PATH}/removeVagrant.sh /home/${SYSTEM_USER}/
# sed -i "s/USER/${SYSTEM_USER}/g" /home/${SYSTEM_USER}/removeVagrant.sh
# chmod 755 /home/${SYSTEM_USER}/removeVagrant.sh
# systemctl daemon-reload
# systemctl enable removeVagrant.service

# Clear synced files
rm -rf ${CURRENT_PATH}/* ${CURRENT_PATH}/.gitignore

# Remove logs
find /var/log/ -type f -exec bash -c 'cat /dev/null > {}' \;
find /var/ossec/logs -type f -execdir sh -c 'cat /dev/null > "$1"' _ {} \;
find /var/log/wazuh-indexer -type f -execdir sh -c 'cat /dev/null > "$1"' _ {} \;
find /var/log/filebeat -type f -execdir sh -c 'cat /dev/null > "$1"' _ {} \;
find /usr/share/wazuh-dashboard/data/wazuh/logs -type f -execdir sh -c 'cat /dev/null > "$1"' _ {} \;

history -c
shutdown -r now > /dev/null 2>&1