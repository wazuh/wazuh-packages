#!/bin/sh
# postremove script for wazuh-agent
# Wazuh, Inc 2015

if getent passwd wazuh; then
  userdel wazuh
fi

if getent group wazuh; then
  groupdel wazuh
fi
