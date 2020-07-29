#/bin/bash
set -exf
# Variables
repo_branch=$(echo "$1" | cut -c1-3)
repo_baseurl=$(echo "$1" | cut -c1-2)
WAZUH_VERSION=$1
ELK_VERSION=$2
STATUS_PACKAGES=$3
DIRECTORY=$4
ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`
ELK_MINOR=`echo ${ELK_VERSION}|cut -d"." -f2`
config_files="/vagrant/Config_files"
automatic_set_ram_location="/etc/"
libraries_files="/vagrant/Libraries/"


. ${libraries_files}wazuh_functions.sh
. ${libraries_files}elastic_functions.sh

cp ${libraries_files}/"automatic_set_ram.sh" ${automatic_set_ram_location}
chmod +x "${automatic_set_ram_location}/${automatic_set_ram}"
echo "@reboot . /etc/automatic_set_ram.sh" >> ram_cron
crontab ram_cron
rm -rf ram_cron

# Setting wazuh default root password
yes wazuh | passwd root
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Dependences
yum install openssl -y

install_wazuh

elastic_stack_${ELK_MAJOR}

rm -rf /vagrant

systemctl stop kibana
systemctl stop  elasticsearch
systemctl stop wazuh-manager
systemctl stop wazuh-api
