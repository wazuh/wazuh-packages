#/bin/bash

set -exf

WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
BRANCH=$5
BRANCHDOC=$6
INSTALLER="all-in-one-installation.sh"

echo "Using ${PACKAGES_REPOSITORY} packages"

adduser wazuh
yes wazuh | sudo passwd wazuh
gpasswd -a wazuh wheel

hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

curl -so ${INSTALLER} https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCHDOC}/resources/open-distro/unattended-installation/${INSTALLER} 

CURRENT_W=$(less ${INSTALLER} | grep "WAZUH_VER=")
CURRENT_O=$(less ${INSTALLER} | grep "OD_VER=")
CURRENT_E=$(less ${INSTALLER} | grep "ELK_VER=")

# Change wazuh and documentation repository branch
sed -i "s/uh\/[0-9]\+\.[0-9]\+\/ex/uh\/${BRANCH}\/ex/g" ${INSTALLER}
sed -i "s/on\/[0-9]\+\.[0-9]\+\/re/on\/${BRANCHDOC}\/re/g" ${INSTALLER}

# Change versions
sed -i "s/${CURRENT_W}/WAZUH_VER=\"${WAZUH_VERSION}\"/g" ${INSTALLER}
sed -i "s/${CURRENT_O}/OD_VER=\"${OPENDISTRO_VERSION}\"/g" ${INSTALLER}
sed -i "s/${CURRENT_E}/ELK_VER=\"${ELK_VERSION}\"/g" ${INSTALLER}

# Change repository if dev is specified
if [ "${PACKAGES_REPOSITORY}" = "dev" ]; then
  sed -i "s/\[wazuh\]/\[wazuh_pre_release\]/g" ${INSTALLER}
  sed -i "s/ngpgkey\=https\:\/\/packages\.wazuh\.com/ngpgkey\=https\:\/\/packages\-dev\.wazuh\.com/g" ${INSTALLER}
  sed -i "s/baseurl\=https\:\/\/packages\.wazuh\.com\/4\.x/baseurl\=https\:\/\/packages\-dev\.wazuh\.com\/pre\-release/g" ${INSTALLER}
  sed -i "s/https\:\/\/packages\.wazuh\.com\/4\.x\/ui\/kibana/https\:\/\/packages\-dev\.wazuh\.com\/pre\-release\/ui\/kibana/g" ${INSTALLER}
  sed -i "s/wazuh_kibana-[0-9\.]\+_[0-9\.]\+/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}/g" ${INSTALLER}
fi

sh ${INSTALLER}
rm ${INSTALLER}

# Check kibana status
until [[ "$(curl -u admin:admin -XGET https://localhost/status -I -s -k | grep HTTP)" == *"200"* ]]; do
    echo "Waiting for Kibana..."
    sleep 2
done

systemctl stop kibana filebeat elasticsearch wazuh-manager
systemctl enable wazuh-manager

# Enable ossec_auth modules
sed -i '/<auth>/ {N; s/<auth>.*yes/<auth>\n\ \ \ \ <disabled>no/g}' /var/ossec/etc/ossec.conf

# Edit window title
sed -i "s/null, \"Elastic\"/null, \"Wazuh\"/g" /usr/share/kibana/src/core/server/rendering/views/template.js

curl -so /vagrant/custom_welcome.tar.gz https://wazuh-demo.s3-us-west-1.amazonaws.com/custom_welcome_opendistro_docker.tar.gz
tar -xf /vagrant/custom_welcome.tar.gz -C /vagrant

cp /vagrant/custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/src/core/server/core_app/assets/
cp /vagrant/custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/src/core/server/core_app/assets/
cp /vagrant/custom_welcome/template.js.hbs /usr/share/kibana/src/legacy/ui/ui_render/bootstrap/template.js.hbs

# Add custom configuration to css
less /vagrant/assets/customWelcomeKibana.css >> /usr/share/kibana/src/core/server/core_app/assets/legacy_light_theme.css

# Get actual RAM of machine and split it in half
ram=$(( $(free -m | awk '/^Mem:/{print $2}') / 2 ))

# Change de jvm.options with the new RAM use
sed -i "s/^-Xms[0-9]\+[gm]/-Xms${ram}m/" /etc/elasticsearch/jvm.options
sed -i "s/^-Xmx[0-9]\+[gm]/-Xmx${ram}m/" /etc/elasticsearch/jvm.options

userdel -rf vagrant
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


yum clean all

# Remove data from /var/ossec/logs/
cd / 
find /var/ossec/logs/ -type f -exec sh -c ': > "$1"' - {} \;

# Remove data from /var/log/ files
find /var/log/ -type f -exec sh -c ': > "$1"' - {} \;

rm securityadmin_demo.sh
history -c

# Temporary fix for missing file content
reboot now
