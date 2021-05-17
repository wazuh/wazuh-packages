#!/bin/bash

# Stop services after reload
systemctl stop wazuh-manager elasticsearch filebeat kibana

# Check disk integrity
fsck /dev/sda1

# Remove everything related to vagrant
userdel -rf vagrant

# Remove logs
cd /
find /var/log/ -type f -exec sh -c \': > \"\$1\"\' - {} \;
find /var/ossec/logs/ -type f -exec sh -c \': > \"\$1\"\' - {} \;

# Clean history
history -c