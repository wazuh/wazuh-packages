#!/bin/bash
set -x

wazuh_branch=$1
forge_token=$2

wazuh_version=""

destination_dir="/wazuh_puppet_module"
version_file="VERSION"

download_sources() {
    if ! curl -L https://github.com/wazuh/wazuh-puppet/tarball/${wazuh_branch} | tar zx ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi
    cd wazuh-*
    wazuh_version=$(grep -oP '^WAZUH-PUPPET_VERSION="\K[^"]+' ${version_file} | cut -d 'v' -f 2)
}

publish_module() {
    curl -X POST -H "Authorization: Bearer ${forge_token}" -H 'Content-Type: application/json' -d '{"file": "'$(base64 -w 0 ${destination_dir}/cbordon-test-${wazuh_version}.tar.gz)'"}' https://forgeapi.puppet.com/v3/releases
}

build_module() {

    download_sources

    pdk build --force --target-dir=${destination_dir}

    ls -la ${destination_dir}

    publish_module

    exit 0
}

build_module
