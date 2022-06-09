#!/bin/bash

# Wazuh-indexer base builder
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

opensearch_version="${1}"
future="${2}"
reference="${3}"
BASE_DIR=/tmp/output/wazuh-indexer-base
VERSION=$(cat /root/VERSION)

# -----------------------------------------------------------------------------

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
fi

if [ "${future}" == "yes" ];then
    VERSION="99.99.0"
fi

# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch/"${opensearch_version}"/opensearch-"${opensearch_version}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-"${opensearch_version}" "${BASE_DIR}"
cd "${BASE_DIR}"
find -type l -exec rm -rf {} \;
find -name "*.bat" -exec rm -rf {} \;
rm -rf README.md manifest.yml opensearch-tar-install.sh logs
sed -i 's|OPENSEARCH_DISTRIBUTION_TYPE=tar|OPENSEARCH_DISTRIBUTION_TYPE=rpm|g' bin/opensearch-env
cp -r /root/stack/indexer/base/files/systemd-entrypoint bin/
cp -r /root/stack/indexer/base/files/etc ./
cp -r /root/stack/indexer/base/files/usr ./
cp -r ./config/log4j2.properties ./etc/wazuh-indexer/
cp -r ./config/opensearch-reports-scheduler ./etc/wazuh-indexer/
cp -r ./config/opensearch-observability ./etc/wazuh-indexer/
cp -r ./config/jvm.options.d ./etc/wazuh-indexer/
rm -rf ./config
rm -rf ./plugins/opensearch-security/tools/install_demo_configuration.sh
cp /root/VERSION .

# -----------------------------------------------------------------------------

# Compile systemD module
git clone https://github.com/opensearch-project/OpenSearch.git --branch="${opensearch_version}" --depth=1
cd OpenSearch/modules/systemd
export JAVA_HOME=/etc/alternatives/java_sdk_11
../../gradlew build || true
mkdir -p "${BASE_DIR}"/modules/systemd
cp build/distributions/systemd-"${opensearch_version}"-SNAPSHOT.jar "${BASE_DIR}"/modules/systemd/systemd-"${opensearch_version}".jar
cp build/resources/test/plugin-security.policy "${BASE_DIR}"/modules/systemd/
cp build/generated-resources/plugin-descriptor.properties "${BASE_DIR}"/modules/systemd/
sed -i 's|-SNAPSHOT||g' "${BASE_DIR}"/modules/systemd/plugin-descriptor.properties
cd "${BASE_DIR}"
rm -rf OpenSearch

# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar -Jcvf wazuh-indexer-base-${VERSION}-linux-x64.tar.xz wazuh-indexer-base
rm -rf "${BASE_DIR}"