#/bin/bash

set -exf

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
PACKAGE_VERSION=$5
INSTALLER="all-in-one-installation.sh"

# Display dev/prod
echo "Using ${PACKAGES_REPOSITORY} packages"

# OVA Welcome message
cat > /etc/issue <<EOF

Welcome to the Wazuh OVA version 
Wazuh - ${WAZUH_VERSION}
Open Distro for Elasticsearch - ${OPENDISTRO_VERSION}
ELK - ${ELK_VERSION}
Access the Wazuh Web Interface at https://\4{eth0}
Thank you for using Wazuh!

EOF

# User Welcome message
cat > /etc/motd <<EOF

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

EOF


# Create user wazuh - Ignore password error
adduser wazuh
yes wazuh | sudo passwd wazuh

# Grant sudo privileges to user
gpasswd -a wazuh wheel

# Disable root access
sed -i "s/root:x:0:0:root:\/root:\/bin\/bash/root:x:0:0:root:\/root:\/sbin\/nologin/" /etc/passwd

# Set Hostname
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Download unattended installer
curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${PACKAGE_VERSION}/resources/open-distro/unattended-installation/${INSTALLER} 

# Get currents version values of installer
ACTUAL_W=$(less ${INSTALLER} | grep "WAZUH_VER=")
ACTUAL_O=$(less ${INSTALLER} | grep "OD_VER=")
ACTUAL_E=$(less ${INSTALLER} | grep "ELK_VER=")

# Change specified versions in unattended installer
sed -i "s/${ACTUAL_W}/WAZUH_VER=\"${WAZUH_VERSION}\"/g" ${INSTALLER}
sed -i "s/${ACTUAL_O}/OD_VER=\"${OPENDISTRO_VERSION}\"/g" ${INSTALLER}
sed -i "s/${ACTUAL_E}/ELK_VER=\"${ELK_VERSION}\"/g" ${INSTALLER}

# Execute unattended installer
sh ${INSTALLER}

# Remove installer
rm ${INSTALLER}

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

# Remove vagrant user - by default this script runs in /home/vagrant 
userdel -rf vagrant

# Remove vagrant shared folder
rm -rf /vagrant
