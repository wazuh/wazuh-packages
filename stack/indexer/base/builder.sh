#!/bin/bash

set -x

# Wazuh-indexer base builder
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

architecture="$1"
revision="$2"
future="$3"
reference="$4"
opensearch_version="2.10.0"
base_dir=/opt/wazuh-indexer-base

# -----------------------------------------------------------------------------

if [ -z "${revision}" ]; then
    revision="1"
fi

if [ "${architecture}" = "x86_64" ] || [ "${architecture}" = "amd64" ]; then
    architecture="x64"
fi

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
    version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${reference}/VERSION | cat)
else
    version=$(cat /root/VERSION)
fi

if [ "${future}" = "yes" ];then
    version="99.99.0"
fi



# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /opt

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch/"${opensearch_version}"/opensearch-"${opensearch_version}"-linux-${architecture}.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-"${opensearch_version}" "${base_dir}"
cd "${base_dir}"
find -type l -exec rm -rf {} \;
find -name "*.bat" -exec rm -rf {} \;
rm -rf README.md manifest.yml opensearch-tar-install.sh logs
sed -i 's|OPENSEARCH_DISTRIBUTION_TYPE=tar|OPENSEARCH_DISTRIBUTION_TYPE=rpm|g' bin/opensearch-env
sed -i 's|"$OPENSEARCH_HOME"/config|/etc/wazuh-indexer|g' bin/opensearch-env
cp -r /root/stack/indexer/base/files/systemd-entrypoint bin/
mkdir -p ./etc/wazuh-indexer/
cp -r ./config/* ./etc/wazuh-indexer/
rm -rf ./config
cp -r /root/stack/indexer/base/files/etc/wazuh-indexer/* ./etc/wazuh-indexer/
cp -r /root/stack/indexer/base/files/etc/sysconfig ./etc/
cp -r /root/stack/indexer/base/files/etc/init.d ./etc/
cp -r /root/stack/indexer/base/files/usr ./
rm -rf ./plugins/opensearch-security/tools/install_demo_configuration.sh
cp /root/VERSION .

# -----------------------------------------------------------------------------

# Compile systemD module
git clone https://github.com/opensearch-project/OpenSearch.git --branch="${opensearch_version}" --depth=1
cd OpenSearch/modules/systemd
export JAVA_HOME=/etc/alternatives/java_sdk_11
../../gradlew build || true
mkdir -p "${base_dir}"/modules/systemd
cp build/distributions/systemd-"${opensearch_version}"-SNAPSHOT.jar "${base_dir}"/modules/systemd/systemd-"${opensearch_version}".jar
cp build/resources/test/plugin-security.policy "${base_dir}"/modules/systemd/
cp build/generated-resources/plugin-descriptor.properties "${base_dir}"/modules/systemd/
sed -i 's|-SNAPSHOT||g' "${base_dir}"/modules/systemd/plugin-descriptor.properties
cd "${base_dir}"
rm -rf OpenSearch

find -type d -exec chmod 750 {} \;
find -type f -perm 644 -exec chmod 640 {} \;
find -type f -perm 664 -exec chmod 660 {} \;
find -type f -perm 755 -exec chmod 750 {} \;
find -type f -perm 744 -exec chmod 740 {} \;

# -----------------------------------------------------------------------------

# Base output
cd /opt
tar -Jcvf wazuh-indexer-base-"${version}"-"${revision}"-linux-${architecture}.tar.xz wazuh-indexer-base
cp wazuh-indexer-base-"${version}"-"${revision}"-linux-${architecture}.tar.xz /tmp/output
