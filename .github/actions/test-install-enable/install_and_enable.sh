#!/bin/bash
set -x
ls -la /packages
echo "Installing Wazuh $2."
source /etc/os-release
if [ "$ID" = "centos" ] && [ "$VERSION_ID" = "8" ]; then
    find /etc/yum.repos.d/ -type f -exec sed -i 's/mirrorlist/#mirrorlist/g' {} \;
    find /etc/yum.repos.d/ -type f -exec sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' {} \;
fi
yum install -y "/packages/$1"

echo "Enabling Wazuh $2."
systemctl enable wazuh-$2
if [ "$?" -eq 0 ]; then
    echo "Wazuh $2 enabled - Test passed correctly."
    exit 0
else 
    echo "Error: Wazuh $2 not enabled."
    exit 1
fi
set +x