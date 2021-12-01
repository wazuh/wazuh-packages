#!/bin/bash
bash ${GITHUB_WORKSPACE}/unattended_scripts/unattended_installation.sh
find / -name "unattended_installation.sh" -exec cat {} \;
echo "Testing"
cat /var/log/wazuh-unattended-installation.log
sleep 60
cd ~
/usr/testing/bin/pytest --tb=long /test_unattended.py -v