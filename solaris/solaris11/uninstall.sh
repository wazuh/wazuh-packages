#/bin/sh

## Stop and remove application
sudo /var/ossec/bin/ossec-control stop
sudo rm -r /var/ossec*
sudo rm /etc/ossec-init.conf

## stop and unload dispatcher
#sudo /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

# remove launchdaemons
sudo rm -f /etc/init.d/wazuh-agent


sudo rm -f /etc/ossec-init.conf


## Remove User and Groups
sudo userdel ossec
sudo groupdel ossec

exit 0
