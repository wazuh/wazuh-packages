#!/bin/bash

DEBUG=$1
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ASSETS_PATH="${CURRENT_PATH}/assets"
CUSTOM_PATH="${ASSETS_PATH}/custom"
SYSTEM_USER="wazuh-user"

systemctl stop wazuh-manager elasticsearch filebeat kibana

# Remove everything related to vagrant
mv ${CUSTOM_PATH}/removeVagrant.service /etc/systemd/system/
sed -i "s/USER/${SYSTEM_USER}/g" /etc/systemd/system/removeVagrant.service
mv ${CUSTOM_PATH}/removeVagrant.sh /home/${SYSTEM_USER}/
sed -i "s/USER/${SYSTEM_USER}/g" /home/${SYSTEM_USER}/removeVagrant.sh
chmod 755 /home/${SYSTEM_USER}/removeVagrant.sh
systemctl daemon-reload
systemctl enable removeVagrant.service

# Clear synced files
rm -rf ${CURRENT_PATH}/* ${CURRENT_PATH}/.gitignore

# Remove logs
find /var/log/ -type f -exec sh -c ': > "$1"' - {} \;
find /var/ossec/logs/ -type f -exec sh -c ': > "$1"' - {} \;

rm /root/anaconda-ks.cfg
rm /root/original-ks.cfg

history -c
shutdown -r now > /dev/null 2>&1
