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
sudo /var/ossec/bin/${control_binary} stop
sudo rm -r /var/ossec*
sudo rm ${OSSEC_INIT}

# remove launchdaemons
sudo rm -f ${OSSEC_INIT}/wazuh-agent

sudo rm -f ${OSSEC_INIT}

## Remove User and Groups
sudo userdel ossec
sudo groupdel ossec

exit 0
