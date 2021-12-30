#!/usr/bin/env bash
set -euo pipefail
curr_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P)"
source "${curr_dir}"/bach.sh


function load-get-config() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" getConfig
}

test-get-config-empty() {
    load-get-config
    @mock logger -e "getConfig must be called with 2 arguments." === @echo "getConfig must be called with 2 arguments."
    getConfig
}

test-get-config-empty-assert() {
    @echo "getConfig must be called with 2 arguments."
    exit 1
}

test-get-config-one-argument() {
    load-get-config
    @mock logger -e "getConfig must be called with 2 arguments." === @echo "getConfig must be called with 2 arguments."
    getConfig "elasticsearch"
}

test-get-config-one-argument-assert() {
    @echo "getConfig must be called with 2 arguments."
    exit 1
}

test-get-config-local() {
    load-get-config
    local base_path=/tmp
    local config_path=example
    local local=1
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-local-assert() {
    cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-online() {
    load-get-config
    local base_path="/tmp"
    local config_path="example"
    resources_config="example.com/config"
    local local=
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-online-assert() {
    curl -so /tmp/elasticsearch/elasticsearch.yml example.com/config/elasticsearch.yml
}

function load-check-system() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" checkSystem
}

test-check-system-no-system() {
    load-check-system
    @mockfalse command -v yum
    @mockfalse command -v zypper
    @mockfalse command -v apt-get
    @mock logger -e "Couldn't find type of system based on the installer software" === @echo "Couldn't find type of system based on the installer software"
    checkSystem
}

test-check-system-no-system-assert() {
    @echo "Couldn't find type of system based on the installer software"
    exit 1
}

test-check-system-yum() {
    load-check-system
    @mocktrue command -v yum
    @mockfalse command -v zypper
    @mockfalse command -v apt-get
    checkSystem
}

test-check-system-yum-assert() {
    sys_type="yum"
    sep="-"
}

test-check-system-zypper() {
    load-check-system
    @mockfalse command -v yum
    @mocktrue command -v zypper
    @mockfalse command -v apt-get
    checkSystem
}

test-check-system-zypper-assert() {
    sys_type="zypper"
    sep="-"
}

test-check-system-apt() {
    load-check-system
    @mockfalse command -v yum
    @mockfalse command -v zypper
    @mocktrue command -v apt-get
    checkSystem
}

test-check-system-yum-assert() {
    sys_type="apt-get"
    sep="="
}