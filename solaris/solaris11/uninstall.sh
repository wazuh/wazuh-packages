#/bin/sh

set -x

INSTALL_PATH=$1

control_binary="wazuh-control"

if [ ! -f /var/ossec/bin/${control_binary} ]; then
  control_binary="ossec-control"
fi

## Stop and remove application
sudo ${INSTALL_PATH}/bin/${control_binary} stop
sudo rm -r /var/ossec*

# remove launchdaemons
sudo rm -f /etc/init.d/wazuh-agent

## Remove User and Groups
sudo userdel wazuh
sudo groupdel wazuh

exit 0
