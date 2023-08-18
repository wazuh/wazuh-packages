#/bin/sh

## Stop and remove application
sudo /Library/overwatch/bin/wazuh-control stop
sudo /bin/rm -r /Library/overwatch*

## stop and unload dispatcher
#sudo /bin/launchctl unload /Library/LaunchDaemons/com.dns.agent.plist

# remove launchdaemons
sudo /bin/rm -f /Library/LaunchDaemons/com.dns.agent.plist

## remove StartupItems
sudo /bin/rm -rf /Library/StartupItems/WAZUH

## Remove User and Groups
sudo /usr/bin/dscl . -delete "/Users/wazuh"
sudo /usr/bin/dscl . -delete "/Groups/wazuh"

sudo /usr/sbin/pkgutil --forget com.dns.pkg.dns-overwatch
sudo /usr/sbin/pkgutil --forget com.dns.pkg.dns-overwatch-etc

# In case it was installed via Puppet pkgdmg provider

if [ -e /var/db/.puppet_pkgdmg_installed_wazuh-agent ]; then
    sudo rm -f /var/db/.puppet_pkgdmg_installed_wazuh-agent
fi

echo
echo "DNS overwatch correctly removed from the system."
echo

exit 0
