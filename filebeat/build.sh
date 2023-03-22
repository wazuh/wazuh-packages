#!/bin/bash
set -e

w_beats_branch="v7.10.2"
w_wazuh_branch=$1
w_filename=$2

download_sources() {
    cd /tmp
    git clone https://github.com/elastic/beats.git -b $w_beats_branch --single-branch --depth=1  > /dev/null 2>&1
    cd beats/filebeat/ > /dev/null 2>&1
    go get > /dev/null 2>&1
    make
    make create-module MODULE=wazuh
    rm -rf module/wazuh/*

    # Fetch Wazuh module source files
    cd /tmp
    git clone https://github.com/wazuh/wazuh -b $w_wazuh_branch --single-branch --depth=1 > /dev/null 2>&1
    cd /tmp/beats/filebeat
    cp -R /tmp/wazuh/extensions/filebeat/7.x/wazuh-module/* module/wazuh
}

build_module() {

    download_sources

    # Generate production files for Wazuh module
    make update 
    cd build/package/module
    chown root:root -R wazuh/
    tar -czvf $w_filename wazuh/* > /dev/null 2>&1

    # Move final package to /tmp/$W_FILENAME
    mv $w_filename /tmp/output

    exit 0
}

build_module
