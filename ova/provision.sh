#/bin/bash
set -exf
# Variables
repo_branch=$(echo "$1" | cut -c1-3)
repo_baseurl=$(echo "$1" | cut -c1-2)
WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
PACKAGES_REPOSITORY=$4
BRANCH=$5
UI_REVISION=$6
DIRECTORY="/var/ossec"
ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`
ELK_MINOR=`echo ${ELK_VERSION}|cut -d"." -f2`

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
config_files="${CURRENT_PATH}/Config_files"
automatic_set_ram_location="/etc/"
libraries_files="${CURRENT_PATH}/Libraries/"

echo "${PACKAGES_REPOSITORY}"


. ${CURRENT_PATH}/Libraries/provision-opendistro.sh


# Setting wazuh default root password

cp ${libraries_files}/automatic_set_ram.sh ${automatic_set_ram_location}
chmod +x "${automatic_set_ram_location}/automatic_set_ram.sh"
echo "@reboot . /etc/automatic_set_ram.sh" >> ram_cron


crontab ram_cron
rm -rf ram_cron

yes wazuh | passwd root
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# OVA Welcome message
cat > /etc/issue << EOF

Welcome to the Wazuh OVA version $WAZUH_VERSION
Access the Wazuh Web Interface at https://\4{eth0}
Thank you for using Wazuh!

EOF

cat > /etc/motd << EOF

                (,                        ((
               ((((                      ((((
              ,(((((                    (((((
              (((((((                  (((((((
             ((((((((((              ,(((((((((
            ((((((((((((            ((((((((((((
           ,((((((((((((((((((((((((((((((((((((
           ((((((((((((((((((((((((((((((((((((((
        ,((((((((((((((((((((((((((((((((((((((((((,
      ((((((((((((((((((((((((((((((((((((((((((((((((
    (((((((((((((((((((((((((((((((((((((((((((((((((((,
     (((((((((( (((((((((((((((((((((((((((( ((((((((((
        ,((((((((, ,((((((((((((((((((((, ,((((((((,,
           (((((((((  (((((((((((((((( ((((((((((
             ,((((((((,,,((,,((,,((,,(((((((((,
                (((((((((( (((((( ((((((((((
                  ,,((((((((((((((((((((,,
                     ((((((((((((((((((
                     ,((((((((((((((((
                       ((((((((((((((
                        ((((((((((((
                         ((((((((((
                          ,,,,,,,,


             WAZUH Open Source Security Platform
                 Site: http://www.wazuh.com

EOF


# Dependences
yum install openssl -y

installPrerequisites
addWazuhrepo
addElasticRepo
installWazuh
installElasticsearch
installFilebeat
installKibana
configWazuh
checkInstallation
cleanInstall

rm -rf /vagrant

systemctl stop kibana filebeat elasticsearch
systemctl enable wazuh-manager
