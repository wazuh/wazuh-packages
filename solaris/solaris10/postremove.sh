#!/bin/sh
# postremove script for wazuh-agent
# Wazuh, Inc 2015-2022

if getent passwd | grep "^wazuh"; then
  userdel wazuh
fi

if getent group | grep "^wazuh"; then
  groupdel wazuh
fi
