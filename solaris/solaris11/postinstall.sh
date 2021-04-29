#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020

if [ -d <INSTALL_PATH>/logs/ossec ]; then
  rm -rf <INSTALL_PATH>/logs/wazuh
  cp -rp <INSTALL_PATH>/logs/ossec <INSTALL_PATH>/logs/wazuh
fi
if [ -d <INSTALL_PATH>/queue/ossec ]; then
  rm -rf <INSTALL_PATH>/queue/sockets
  cp -rp <INSTALL_PATH>/queue/ossec <INSTALL_PATH>/queue/sockets
fi

# Remove old ossec user and group if exists and change ownwership of files

if grep "^ossec:" /etc/group > /dev/null 2>&1; then
  find <INSTALL_PATH> -group ossec -user root -exec chown root:wazuh {} \; > /dev/null 2>&1 || true
  if grep "^ossec" /etc/passwd > /dev/null 2>&1; then
    find <INSTALL_PATH> -group ossec -user ossec -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossec
  fi
  if grep "^ossecm" /etc/passwd > /dev/null 2>&1; then
    find <INSTALL_PATH> -group ossec -user ossecm -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossecm
  fi
  if grep "^ossecr" /etc/passwd > /dev/null 2>&1; then
    find <INSTALL_PATH> -group ossec -user ossecr -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossecr
  fi
  groupdel ossec
fi

rm -rf <INSTALL_PATH>/logs/ossec/
rm -rf <INSTALL_PATH>/queue/ossec/
