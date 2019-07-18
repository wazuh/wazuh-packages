#/bin/bash
# Variables
repo_branch=$(echo "$1" | cut -c1-3)
repo_baseurl=$(echo "$1" | cut -c1-2)
WAZUH_VERSION=$1
ELK_VERSION=$2
STATUS_PACKAGES=$3
DIRECTORY=$4
ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`
ELK_MINOR=`echo ${ELK_VERSION}|cut -d"." -f2`
config_files="/vagrant/config_files"

. /vagrant/libraries/wazuh_functions.sh
. /vagrant/libraries/elastic_functions.sh

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
