#!/bin/sh
# preremove script for wazuh-agent

OSSEC_INIT="/etc/ossec-init.conf"
control_binary="wazuh-control"

. ${OSSEC_INIT}

set_control_binary() {
  number_version=`echo "${VERSION}" | cut -d v -f 2`
  major=`echo $number_version | cut -d . -f 1`
  minor=`echo $number_version | cut -d . -f 2`

  if [ "$major" -le "4" ] && [ "$minor" -le "1" ]; then
    control_binary="ossec-control"
  fi
}

set_control_binary

/var/ossec/bin/${control_binary} stop
