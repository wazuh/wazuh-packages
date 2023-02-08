#!/bin/bash
echo "Installing Wazuh $2."

if [ -f /etc/os-release ]; then
    source /etc/os-release
    if [ "$ID" = "centos" ] && [ "$VERSION_ID" = "8" ]; then
        find /etc/yum.repos.d/ -type f -exec sed -i 's/mirrorlist/#mirrorlist/g' {} \;
        find /etc/yum.repos.d/ -type f -exec sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' {} \;
    fi
fi

if [ -f /etc/redhat-release ]; then
    VERSION=$(cat /etc/redhat-release)
    if [ "$VERSION" = "CentOS release 5.11 (Final)" ] || [ "$VERSION" = "CentOS release 6.9 (Final)" ]; then
        rm -rf /etc/yum.repos.d/*
    fi
fi

if [ -n "$(command -v yum)" ]; then
    sys_type="yum"
elif [ -n "$(command -v apt-get)" ]; then
    sys_type="apt-get"
    apt-get update
    apt-get install -y systemd
else
    common_logger -e "Couldn't find type of system"
    exit 1
fi

$sys_type install -y "/packages/$1"