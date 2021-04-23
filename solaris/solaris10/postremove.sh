#!/bin/sh
# postremove script for wazuh-agent

if getent passwd | grep "^wazuh"; then
  userdel wazuh
fi

if getent group | grep "^wazuh"; then
  groupdel wazuh
fi
