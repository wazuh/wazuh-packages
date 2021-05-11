#!/bin/ksh
# postinst script for wazuh-agent
# Wazuh, Inc 2015-2020

OSSEC_HIDS_TMP_DIR="/tmp/wazuh-agent"
DIR="/var/ossec"

# Restore the agent.confs, client.keys and local_internal_options
if [ -f ${OSSEC_HIDS_TMP_DIR}/client.keys ]; then
    cp ${OSSEC_HIDS_TMP_DIR}/client.keys ${DIR}/etc/client.keys
fi
# Restore agent.conf configuration
if [ -f ${OSSEC_HIDS_TMP_DIR}/agent.conf ]; then
    mv ${OSSEC_HIDS_TMP_DIR}/agent.conf ${DIR}/etc/agent.conf
    chmod 640 ${DIR}/etc/agent.conf
fi
# Restore client.keys configuration
if [ -f ${OSSEC_HIDS_TMP_DIR}/local_internal_options.conf ]; then
    mv ${OSSEC_HIDS_TMP_DIR}/local_internal_options.conf ${DIR}/etc/local_internal_options.conf
fi

# logrotate configuration file
if [ -d /etc/logrotate.d/ ]; then
    if [ -e /etc/logrotate.d/wazuh-hids ]; then
        rm -f /etc/logrotate.d/wazuh-hids
    fi
    cp -p ${DIR}/etc/logrotate.d/wazuh-hids /etc/logrotate.d/wazuh-hids
    chmod 644 /etc/logrotate.d/wazuh-hids
    chown root:root /etc/logrotate.d/wazuh-hids
    rm -rf ${DIR}/etc/logrotate.d
fi

# Service
if [ -f /etc/init.d/wazuh-agent ]; then
        /etc/init.d/wazuh-agent stop > /dev/null 2>&1
fi

## Delete tmp directory
if [ -d ${OSSEC_HIDS_TMP_DIR} ]; then
    rm -r ${OSSEC_HIDS_TMP_DIR}
fi
#
#exit 0
