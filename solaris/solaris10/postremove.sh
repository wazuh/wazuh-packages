#!/bin/sh
# postremove script for wazuh-agent

if getent passwd | grep "^ossec"; then
  userdel ossec
fi

if getent group | grep "^ossec"; then
  groupdel ossec
fi
