#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020
set -x
install_path="<INSTALL_PATH>"

if [ -d ${install_path}/logs/ossec ]; then
  if [ -z "$(ls -A ${install_path}/logs/ossec)" ]; then
    rm -rf ${install_path}/logs/ossec
  else
    rm -rf ${install_path}/logs/wazuh
    mv ${install_path}/logs/ossec ${install_path}/logs/wazuh
  fi
fi  
if [ -d ${install_path}/queue/ossec ]; then
  if [ -z "$(ls -A ${install_path}/queue/ossec)" ]; then
    rm -rf ${install_path}/queue/ossec
  else
    rm -rf ${install_path}/queue/sockets
    mv ${install_path}/queue/ossec/ ${install_path}/queue/sockets
  fi
fi
