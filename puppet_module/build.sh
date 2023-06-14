#!/bin/bash
set -e

wazuh_branch=$1

download_sources() {
    if ! curl -L https://github.com/wazuh/wazuh-puppet/tarball/${wazuh_branch} | tar zx ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi
    cd wazuh-*
}

build_module() {

    download_sources

    pdk build --force --target-dir=/tmp/output/

    exit 0
}

build_module
