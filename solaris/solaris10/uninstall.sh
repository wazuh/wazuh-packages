#/bin/sh

OSSEC_INIT="/etc/ossec-init.conf"
control_binary="wazuh-control"

set_control_binary() {
  wazuh_version=$(grep VERSION ${OSSEC_INIT} | sed 's/VERSION="v//g' | sed 's/"//g')
  number_version=`echo "${wazuh_version}" | cut -d v -f 2`
  major=`echo $number_version | cut -d . -f 1`
  minor=`echo $number_version | cut -d . -f 2`

  if [ "$major" -le "4" ] && [ "$minor" -le "1" ]; then
    control_binary="ossec-control"
  fi
}

set_control_binary

## Stop and remove application
/var/ossec/bin/${control_binary} 2> /dev/null
rm -rf /var/ossec/
rm -f ${OSSEC_INIT}


## stop and unload dispatcher
#/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

# remove launchdaemons
rm -f /etc/init.d/wazuh-agent
rm -f ${OSSEC_INIT}

rm -rf /etc/rc2.d/S97wazuh-agent
rm -rf /etc/rc3.d/S97wazuh-agent


## Remove User and Groups
userdel ossec 2> /dev/null
groupdel ossec 2> /dev/null

exit 0
