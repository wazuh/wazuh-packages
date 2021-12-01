#!/bin/bash
cd ${GITHUB_WORKSPACE}/unattended_scripts
bash ./unattended_installation.sh -A -l
cat /var/log/wazuh-unattended-installation.log
sleep 60
cd ~
/usr/testing/bin/pytest --tb=long /test_unattended.py -v