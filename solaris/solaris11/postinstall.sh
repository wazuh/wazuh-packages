#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020

if [ -d /var/ossec/logs/ossec ]
  mv -r /var/ossec/logs/ossec /var/ossec/logs/wazuh
fi
if [ -d /var/ossec/queue/ossec ]
  mv -r /var/ossec/queue/ossec /var/ossec/queue/sockets
fi
