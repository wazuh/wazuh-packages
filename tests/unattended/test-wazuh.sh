#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../../"$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/tests/bach.sh

@setup-test {
    @ignore logger
}

function load-installWazuh() {
    @load_function "${base_dir}/tests/unattended/wazuh.sh" installWazuh
}

test-installWazuh-zypper-error() {
    load-installWazuh
    sys_type="zypper"
    wazuh_version=1
    wazuh_revision=1
    @mock zypper -n install wazuh-manager=1-1 === @real false
    installWazuh
}

test-installWazuh-zypper-error-assert() {
    rollBack
    exit 1
}

test-installWazuh-apt-error() {
    load-installWazuh
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    @mock apt-get install wazuh-manager=1-1 -y === @real false
    installWazuh
}

test-installWazuh-apt-error-assert() {
    rollBack
    exit 1
}

test-installWazuh-yum-error() {
    load-installWazuh
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    @mock yum install wazuh-manager-1-1 -y === @real false
    installWazuh
}

test-installWazuh-yum-error-assert() {
    rollBack
    exit 1
}

test-installWazuh-zypper() {
    load-installWazuh
    sys_type="zypper"
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-installWazuh-zypper-assert() {
    zypper -n install wazuh-manager=1-1
    @echo 1
}

test-installWazuh-apt() {
    load-installWazuh
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-installWazuh-apt-assert() {
    apt-get install wazuh-manager=1-1 -y
    @echo 1
}

test-installWazuh-yum() {
    load-installWazuh
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-installWazuh-yum-assert() {
    yum install wazuh-manager-1-1 -y
    @echo 1
}

function load-configureWazuhCluster() {
    @load_function "${base_dir}/tests/unattended/wazuh.sh" configureWazuhCluster
}

