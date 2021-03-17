#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020

if [ -d <INSTALL_PATH>/logs/ossec ]; then
  mv <INSTALL_PATH>/logs/ossec/* <INSTALL_PATH>/logs/wazuh
fi
if [ -d <INSTALL_PATH>/queue/ossec ]; then
  mv <INSTALL_PATH>/queue/ossec/* <INSTALL_PATH>/queue/sockets
fi

# Change user and group if necessary
find <INSTALL_PATH> -group ossec -user root -exec chown root:wazuh {} \; || true
find <INSTALL_PATH> -group ossec -user ossec -exec chown wazuh:wazuh {} \; || true
find <INSTALL_PATH> -group ossec -user ossecm -exec chown wazuh:wazuh {} \; || true
find <INSTALL_PATH> -group ossec -user ossecr -exec chown wazuh:wazuh {} \; || true

rm -rf <INSTALL_PATH>/logs/ossec/
rm -rf <INSTALL_PATH>/queue/ossec/
