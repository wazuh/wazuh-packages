#!/bin/bash

# Wazuh-indexer base builder
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

OPENSEARCH_VERSION="${1}"
FUTURE="${2}"
REVISION="${3}"
REFERENCE="${4}"
BASE_DIR=/tmp/output/wazuh-indexer-base

# -----------------------------------------------------------------------------

# Including files
if [ "${REFERENCE}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${REFERENCE}" | tar xz
    cp -r ./wazuh*/* /root/
    VERSION=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${REFERENCE}/VERSION | cat)
else
    VERSION=$(cat /root/VERSION)
fi

if [ "${FUTURE}" == "yes" ];then
    VERSION="99.99.0"
fi



# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch/"${OPENSEARCH_VERSION}"/opensearch-"${OPENSEARCH_VERSION}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-"${OPENSEARCH_VERSION}" "${BASE_DIR}"
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
git clone https://github.com/opensearch-project/OpenSearch.git --branch="${OPENSEARCH_VERSION}" --depth=1
cd OpenSearch/modules/systemd
export JAVA_HOME=/etc/alternatives/java_sdk_11
../../gradlew build || true
mkdir -p "${BASE_DIR}"/modules/systemd
cp build/distributions/systemd-"${OPENSEARCH_VERSION}"-SNAPSHOT.jar "${BASE_DIR}"/modules/systemd/systemd-"${OPENSEARCH_VERSION}".jar
cp build/resources/test/plugin-security.policy "${BASE_DIR}"/modules/systemd/
cp build/generated-resources/plugin-descriptor.properties "${BASE_DIR}"/modules/systemd/
sed -i 's|-SNAPSHOT||g' "${BASE_DIR}"/modules/systemd/plugin-descriptor.properties
cd "${BASE_DIR}"
rm -rf OpenSearch

# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar -Jcvf wazuh-indexer-base-"${VERSION}"-"${REVISION}"-linux-x64.tar.xz wazuh-indexer-base
rm -rf "${BASE_DIR}"