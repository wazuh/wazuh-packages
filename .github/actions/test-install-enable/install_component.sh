#!/bin/bash
echo "Installing Wazuh $2."

source /etc/os-release
if [ "$ID" = "centos" ] && [ "$VERSION_ID" = "8" ]; then
    find /etc/yum.repos.d/ -type f -exec sed -i 's/mirrorlist/#mirrorlist/g' {} \;
    find /etc/yum.repos.d/ -type f -exec sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' {} \;
fi

if [ -n "$(command -v yum)" ]; then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ]; then
    sys_type="apt-get"
    apt-get update
    apt-get install -y systemd
elif [ -n "$(command -v zypper)" ]; then
    sys_type="zypper"
else
    common_logger -e "Couldn't find type of system"
    exit 1
fi

$sys_type install -y "/packages/$1"