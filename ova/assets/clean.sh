#!/bin/bash

DEBUG=$1
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"

# Stop services after reload
systemctl stop wazuh-manager elasticsearch filebeat kibana

# Set dinamic ram of vm
mv ${CURRENT_PATH}/assets/automatic_set_ram.sh /etc/
chmod +x "/etc/automatic_set_ram.sh"
echo "@reboot . /etc/automatic_set_ram.sh" >> cron
crontab cron
rm cron

# Remove everything related to vagrant
mv ${CURRENT_PATH}/assets/removeVagrant.service /etc/systemd/system/
mv ${CURRENT_PATH}/assets/removeVagrant.sh /home/wazuh/
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
shutdown -r now
