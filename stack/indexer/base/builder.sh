#!/bin/bash

# Wazuh-indexer base builder
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

reference=$1
version=$2
BASE_DIR=/tmp/output/wazuh-indexer-base

# -----------------------------------------------------------------------------

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${reference} | tar xzf
    cp -r ./wazuh*/* /root/
fi

if [ -z "${version}" ]; then
    version=1.2.4
fi

# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

curl -OL https://artifacts.opensearch.org/releases/bundle/opensearch/"${version}"/opensearch-"${version}"-linux-x64.tar.gz | tar xzf

mv opensearch-"${version}" "${BASE_DIR}"
cd "${BASE_DIR}"
find -type l -exec rm -rf {} \;
rm -rf README.md manifest.yml opensearch-tar-install.sh logs
sed -i 's|OPENSEARCH_DISTRIBUTION_TYPE=tar|OPENSEARCH_DISTRIBUTION_TYPE=rpm|g' bin/opensearch-env
cp -r /root/stack/indexer/base/files/systemd-entrypoint bin/
cp -r /root/stack/indexer/base/files/etc ./
cp -r /root/stack/indexer/base/files/usr ./
cp -r ./config/opensearch-reports-scheduler ./etc/wazuh-indexer/
cp -r ./config/opensearch-observability ./etc/wazuh-indexer/
cp -r ./config/jvm.options.d ./etc/wazuh-indexer/
rm -rf ./config

# -----------------------------------------------------------------------------

# Compile systemD module
git clone https://github.com/opensearch-project/OpenSearch.git --branch="${version}" --depth=1
cd OpenSearch/modules/systemd
export JAVA_HOME=/etc/alternatives/java_sdk_11
../../gradlew build || true
cp build/distributions/systemd-"${version}"-SNAPSHOT.jar "${BASE_DIR}"/modules/systemd/systemd-"${version}".jar
cp build/resources/test/plugin-security.policy "${BASE_DIR}"/modules/systemd/
cp build/generated-resources/plugin-descriptor.properties "${BASE_DIR}"/modules/systemd/
sed -i 's|-SNAPSHOT||g' "${BASE_DIR}"/modules/systemd/plugin-descriptor.properties
cd "${BASE_DIR}"
rm -rf OpenSearch

# -----------------------------------------------------------------------------

cd /tmp/output
tar cvf wazuh-indexer-base-linux-x64.tar.gz wazuh-indexer-base 