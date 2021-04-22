#/bin/bash

set -exf

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
INSTALLER=$5

# Display dev/prod
echo "Using ${PACKAGES_REPOSITORY} packages"

# OVA Welcome message
echo -e '

Welcome to the Wazuh OVA version 
Wazuh - ${WAZUH_VERSION}
Open Distro for Elasticsearch - ${OPENDISTRO_VERSION}
Filebeat - ${ELK_VERSION}
Access the Wazuh Web Interface at https://\4{eth0} or https://\4{eth1}
Thank you for using Wazuh!

' > /etc/issue

echo -e '

              W.                   W.
             WWW.                 WWW.
            WWWWW.               WWWWW.
           WWWWWWW.             WWWWWWW.
          WWWWWWWWW.           WWWWWWWWW.
         WWWWWWWWWWW.         WWWWWWWWWWW.
        WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
       WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
     WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
    WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
  WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW.
  WWWWWWWW...WWWWWWWWWWWWWWWWWWWWWWWW...WWWWWWWW.
    WWWWWWWW...WWWWWWWWWWWWWWWWWWWW..WWWWWWWW.
       WWWWWWW...WWWWWWWWWWWWWWWW..WWWWWWWW.
         WWWWWWWW...WWW....WWW...WWWWWWWW.
           WWWWWWWW....WWWW....WWWWWWWW.
              WWWWWWWWWWWWWWWWWWWWWWW.
                WWWWWWWWWWWWWWWWWWW.
                 WWWWWWWWWWWWWWWWW.
                  WWWWWWWWWWWWWWW.
                   WWWWWWWWWWWWW.
                    WWWWWWWWWWW.
                     WWWWWWWWW.
                      WWWWWWW.


         WAZUH Open Source Security Platform
                   www.wazuh.com

' > /etc/motd


# Create user wazuh - Ignore password error
adduser wazuh
yes wazuh | sudo passwd wazuh

# Grant sudo privileges to user
gpasswd -a wazuh wheel

# Remove user vagrant
userdel -rf vagrant

# Disable root access
sed -i "s/root:x:0:0:root:\/root:\/bin\/bash/root:x:0:0:root:\/root:\/sbin\/nologin/" /etc/passwd

# Set Hostname
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Execute unattended installer
sh /vagrant/${INSTALLER}

# Remove installer
rm /vagrant/${INSTALLER}

# Stop services and enable manager
systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager

# Get actual RAM of machine
ram_gb=$(free -m | awk '/^Mem:/{print $2}')

# Split RAM in half
ram=$(( $(free -m | awk '/^Mem:/{print $2}') / 2 ))

# Change de jvm.options with the new RAM use
sed -i "s/-Xms[0-9]\+[gm]/-Xms${ram}m/" "/etc/elasticsearch/jvm.options"
sed -i "s/-Xmx[0-9]\+[gm]/-Xmx${ram}m/" "/etc/elasticsearch/jvm.options"

# Remove vagrant shared folder
rm -rf /vagrant
