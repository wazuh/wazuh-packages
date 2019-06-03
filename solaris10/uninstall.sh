#/bin/sh

## Stop and remove application
/var/ossec/bin/ossec-control stop 2> /dev/null
rm -rf /var/ossec/
rm -f /etc/ossec-init.conf


## stop and unload dispatcher
#/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

# remove launchdaemons
rm -f /etc/init.d/wazuh-agent
rm -f /etc/ossec-init.conf

rm -rf /etc/rc2.d/S97wazuh-agent
rm -rf /etc/rc3.d/S97wazuh-agent


## Remove User and Groups
userdel ossec 2> /dev/null
groupdel ossec 2> /dev/null

exit 0
