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

echo "Enabling Wazuh $2."
if ps -p 1 -o comm= | grep -q "systemd"; then
    systemctl daemon-reload
    systemctl enable wazuh-$2
    output=$(echo $?)
elif ps -p 1 -o comm= | grep -q "init"; then
    chkconfig --add wazuh-$2
    output=$(echo $?)
else
    /etc/rc.d/init.d/wazuh${2} start 
    output=$(echo $?)
fi
if [ "$output" -eq 0 ]; then
    echo "Wazuh $2 enabled - Test passed correctly."
    exit 0
else
    echo "Error: Wazuh $2 not enabled."
    exit 1
fi