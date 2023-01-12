#!/bin/bash

wazuh_branch=$1
forge_token="08788f6be64beb40e4159f488470d585b6b8ec1edd8374f27a97f0b5b7ab14dc"

wazuh_version=""

build_dir="/pkg"
destination_dir="/wazuh_puppet_module"
version_file="${build_dir}/VERSION"

download_sources() {
    if ! curl -L https://github.com/wazuh/wazuh-puppet/tarball/${wazuh_branch} | tar zx ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi
    mv wazuh-* ${build_dir}
    wazuh_version=$(grep -oP '^WAZUH-PUPPET_VERSION="\K[^"]+' ${version_file} | cut -d 'v' -f 2)
}

publish_module() {
    curl -X POST -H "Authorization: Bearer ${forge_token}" -d ${destination_dir}/wazuh-wazuh-${wazuh_version}.tar.gz -H "Content-Type: application/json" https://forgeapi.puppet.com/v3/releases
}

build_module() {

    download_sources

    cd ${build_dir}/wazuh-*

    pdk build --force --target-dir=${destination_dir}

    exit 0
}

build_module