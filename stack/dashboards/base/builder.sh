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
release="${2}"
reference="${3}"
BASE_DIR=/tmp/output/wazuh-dashboards-base

# -----------------------------------------------------------------------------

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
    version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/VERSION | cat)
else
    version=$(cat /root/VERSION)
fi

# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

if [ -z "${release}" ]; then
    release="1"
fi

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/"${opensearch_version}"/opensearch-dashboards-"${opensearch_version}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-dashboards-"${opensearch_version}"-linux-x64 "${BASE_DIR}"
cd "${BASE_DIR}"
find -type l -exec rm -rf {} \;
rm -rf ./config/*
cp -r /root/stack/dashboards/base/files/etc ./


# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar cvf wazuh-dashboards-base-"${version}"-"${release}"-linux-x64.tar.gz wazuh-dashboards-base 
rm -rf "${BASE_DIR}"