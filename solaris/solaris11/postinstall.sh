#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020

if [ -d <INSTALL_PATH>/logs/ossec ]; then
  mv <INSTALL_PATH>/logs/ossec/* <INSTALL_PATH>/logs/wazuh
fi
if [ -d <INSTALL_PATH>/queue/ossec ]; then
  mv <INSTALL_PATH>/queue/ossec/* <INSTALL_PATH>/queue/sockets
fi

rm -rf <INSTALL_PATH>/logs/ossec/
rm -rf <INSTALL_PATH>/queue/ossec/
