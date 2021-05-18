#!/bin/bash

DEBUG=$1
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"

# Stop services after reload
systemctl stop wazuh-manager elasticsearch filebeat kibana

# Remove everything related to vagrant
mv ${CURRENT_PATH}/assets/removeVagrant.sh /home/wazuh/
chmod 755 /home/wazuh/removeVagrant.sh

cat > /etc/systemd/system/removeVagrant.service <<EOF
[Unit]
Description=Remove vagrant

[Install]
WantedBy=multi-user.target

[Service]
ExecStart=/bin/bash /home/wazuh/removeVagrant.sh
Type=simple
User=root
Group=root
WorkingDirectory=/home/wazuh
Restart=always
RestartSec=3
EOF

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
