#!/bin/sh
# preremove script for wazuh-agent

control_binary="wazuh-control"

set_control_binary() {
  if [ ! -f /var/ossec/bin/${control_binary} ]; then
    control_binary="ossec-control"
  fi
}

set_control_binary

/var/ossec/bin/${control_binary} stop
