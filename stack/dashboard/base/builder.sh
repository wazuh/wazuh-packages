#!/bin/bash

# Wazuh package builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
opensearch_version="${1}"
future="${2}"
reference="${3}"
BASE_DIR=/tmp/output/wazuh-dashboard-base

# -----------------------------------------------------------------------------

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
    version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/VERSION | cat)
else
    version=$(cat /root/VERSION)
fi
if [ "${future}" = "yes" ];then
    version="99.99.0"
fi


# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

if [ -z "${release}" ]; then
    release="1"
fi

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/"${opensearch_version}"/opensearch-dashboards-"${opensearch_version}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-dashboards-* "${BASE_DIR}"
cd "${BASE_DIR}"
find -type l -exec rm -rf {} \;
rm -rf ./config/*
cp -r /root/stack/dashboard/base/files/etc ./
find -type d -exec chmod 750 {} \;
find -type f -perm 644 -exec chmod 640 {} \;
find -type f -perm 755 -exec chmod 750 {} \;


# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar -cJf wazuh-dashboard-base-"${version}"-linux-x64.tar.xz wazuh-dashboard-base
rm -rf "${BASE_DIR}"