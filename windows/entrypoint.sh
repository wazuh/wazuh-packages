#!/bin/bash
# Wazuh package builder
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

wazuh_version=$1
revision=$2
msi_name="wazuh-agent-${wazuh_version}-${revision}"

git clone https://github.com/wazuh/wazuh.git
cd wazuh/src
git checkout ${wazuh_version}

make deps
make TARGET=winagent

cd  "/home/wazuh_msi/"
mv ${msi_name} ""
