#/bin/bash
set -x
# Variables
repo_branch=$(echo "$1" | cut -c1-3)
repo_baseurl=$(echo "$1" | cut -c1-2)
WAZUH_VERSION=$1
OPENDISTRO_VERSION=$2
ELK_VERSION=$3
STATUS_PACKAGES=$4
DIRECTORY="/var/ossec"
ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`
ELK_MINOR=`echo ${ELK_VERSION}|cut -d"." -f2`
config_files="/vagrant/Config_files"
automatic_set_ram_location="/etc/"
libraries_files="/vagrant/Libraries/"

echo "${STATUS_PACKAGES}"
. /vagrant/Libraries/provision-opendistro.sh


# Setting wazuh default root password
yes wazuh | passwd root
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Dependences
yum install openssl -y

installPrerequisites
addWazuhrepo
installWazuh
installElasticsearch
installFilebeat
installKibana
checkInstallation
cleanInstall

rm -rf /vagrant

systemctl stop kibana
systemctl filebeat kibana
systemctl stop  elasticsearch
systemctl stop wazuh-manager
systemctl stop wazuh-api
