#!/bin/bash
bash unattended_scripts/open-distro/unattended-installation/unattended-installation.sh
cat /var/log/wazuh-unattended-installation.log
sleep 60
cd ~
/usr/testing/bin/pytest --tb=long /test_unattended.py -v