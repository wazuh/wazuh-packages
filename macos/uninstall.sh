#/bin/sh

## Stop and remove application
sudo /Library/Ossec/bin/ossec-control stop
sudo /bin/rm -r /Library/Ossec*

## stop and unload dispatcher
#sudo /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

# remove launchdaemons
sudo /bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist

## remove StartupItems
sudo /bin/rm -rf /Library/StartupItems/WAZUH

## Remove User and Groups
sudo /usr/bin/dscl . -delete "/Users/wazuh"
sudo /usr/bin/dscl . -delete "/Groups/wazuh"

sudo /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
sudo /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent-etc

# In case it was installed via Puppet pkgdmg provider

if [ -e /var/db/.puppet_pkgdmg_installed_wazuh-agent ]; then
    sudo rm -f /var/db/.puppet_pkgdmg_installed_wazuh-agent
fi

echo
echo "Wazuh agent correctly removed from the system."
echo

exit 0
