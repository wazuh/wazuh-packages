#/bin/bash

set -exf

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
BRANCH=$5
INSTALLER="all-in-one-installation.sh"

# Display dev/prod
echo "Using ${PACKAGES_REPOSITORY} packages"

# Create user wazuh - Ignore password error
adduser wazuh
yes wazuh | sudo passwd wazuh

# Grant sudo privileges to user
gpasswd -a wazuh wheel

# Set Hostname
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

# Download unattended installer
curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/unattended-installation/${INSTALLER} 

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
systemctl stop kibana filebeat elasticsearch wazuh-manager
systemctl enable wazuh-manager

# Disable all host modules
sed -i "s/<disabled>no/<disabled>yes/g" /var/ossec/etc/ossec.conf
sed -i "s/<enabled>yes/<enabled>no/g" /var/ossec/etc/ossec.conf

# Disable /var/log/ files and commands monitoring
sed -i "s/<localfile>/<!--localfile>/g" /var/ossec/etc/ossec.conf
sed -i "s/<\/localfile>/<\/localfile-->/g" /var/ossec/etc/ossec.conf

# Enable rule_test and ossec_auth modules
sed -i '/<auth>/ {N; s/<auth>.*yes/<auth>\n\ \ \ \ <disabled>no/g}' /var/ossec/etc/ossec.conf

# Custom Login Page
# Edit window title
sed -i "s/null, \"Elastic\"/null, \"Wazuh\"/g" /usr/share/kibana/src/core/server/rendering/views/template.js

# Download custom files (background, logo and template)
curl -so /vagrant/custom_welcome.tar.gz https://wazuh-demo.s3-us-west-1.amazonaws.com/custom_welcome_opendistro_docker.tar.gz
tar -xf /vagrant/custom_welcome.tar.gz -C /vagrant

# Copy necesaries files
cp /vagrant/custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/src/core/server/core_app/assets/
cp /vagrant/custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/src/core/server/core_app/assets/
cp /vagrant/custom_welcome/template.js.hbs /usr/share/kibana/src/legacy/ui/ui_render/bootstrap/template.js.hbs

# Add custom configuration to css
less /vagrant/assets/customWelcomeKibana.txt >> /usr/share/kibana/src/core/server/core_app/assets/legacy_light_theme.css

# Get actual RAM of machine and split it in half
ram=$(( $(free -m | awk '/^Mem:/{print $2}') / 2 ))

# Change de jvm.options with the new RAM use
sed -i "s/^-Xms[0-9]\+[gm]/-Xms${ram}m/" /etc/elasticsearch/jvm.options
sed -i "s/^-Xmx[0-9]\+[gm]/-Xmx${ram}m/" /etc/elasticsearch/jvm.options

# Remove vagrant user - by default this script runs in /home/vagrant 
userdel -rf vagrant

# Remove vagrant shared folder
rm -rf /vagrant

# OVA Welcome message
cat > /etc/issue <<EOF

Welcome to the Wazuh OVA version 
Wazuh - ${WAZUH_VERSION}
Open Distro for Elasticsearch - ${OPENDISTRO_VERSION}
ELK - ${ELK_VERSION}
Access the Wazuh Web Interface at https://\4{eth0} with admin/admin
Access this machine with wazuh/wazuh
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

# Clean cache
yum clean all

# Remove data from /var/ossec/logs/
find /var/ossec/logs/ -type f -exec sh -c ': > "$1"' - {} \;

# Remove data from /var/log/ files
find /var/log/ -type f -exec sh -c ': > "$1"' - {} \;

# Delete history
history -c