#!/bin/sh
# Wazuh package builder
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
set -exf
wazuh_version=$1
git clone https://github.com/wazuh/wazuh.git

cd wazuh/src
git checkout ${wazuh_version}

make deps
make TARGET=winagent

wget https://github.com/wixtoolset/wix3/releases/download/wix3111rtm/wix311-binaries.zip
unzip wix311-binaries.zip -d /home/wazuh_msi/wazuh/src/win32/wix

cd  "/home/wazuh_msi/"
cp -rf "/home/wazuh_msi/wazuh" "/home/wazuh_msi/output"
