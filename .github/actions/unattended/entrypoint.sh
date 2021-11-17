#!/bin/bash
bash unattended_scripts/open-distro/unattended-installation/unattended-installation.sh && cd ~ && /usr/testing/bin/pytest --tb=long /test_unattended.py -v