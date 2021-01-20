#!/bin/bash

. /etc/ossec-init.conf 2> /dev/null || exit 1
(sleep 5 && systemctl stop wazuh-agent && yum install $DIRECTORY/var/upgrade/wazuh-agent-4.0.4-1.x86_64.rpm -y >> $DIRECTORY/logs/upgrade.log && echo $? >> $DIRECTORY/var/upgrade/upgrade_result && echo "logcollector.remote_commands=1" >> $DIRECTORY/etc/local_internal_options.conf && echo "wazuh_command.remote_commands=1" >> $DIRECTORY/etc/local_internal_options.conf && echo "sca.remote_commands=1" >> $DIRECTORY/etc/local_internal_options.conf && systemctl restart wazuh-agent) &


