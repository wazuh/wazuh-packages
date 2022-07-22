#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-manager_install() {
    @load_function "${base_dir}/manager.sh" manager_install
}

test-01-manager_install-apt-error() {
    load-manager_install
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    @mockfalse apt-get install wazuh-manager=1-1 -y
    manager_install
}

test-01-manager_install-apt-error-assert() {
    installCommon_rollBack
    exit 1
}

test-02-manager_install-yum-error() {
    load-manager_install
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    @mockfalse yum install wazuh-manager-1-1 -y
    manager_install
}

test-02-manager_install-yum-error-assert() {
    installCommon_rollBack
    exit 1
}


test-03-manager_install-apt() {
    load-manager_install
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    manager_install
    @echo $wazuh_installed
}

test-03-manager_install-apt-assert() {
    apt-get install wazuh-manager=1-1 -y
    @echo 1
}

test-04-manager_install-yum() {
    load-manager_install
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    manager_install
    @echo $wazuh_installed
}

test-04-manager_install-yum-assert() {
    yum install wazuh-manager-1-1 -y
    @echo 1
}

function load-manager_startCluster() {
    @load_function "${base_dir}/manager.sh" manager_startCluster
}

test-05-manager_startCluster() {
    load-manager_startCluster
    server_node_names=("wazuh" "node10")
    server_node_types=("master" "worker")
    server_node_ips=("1.1.1.1" "2.2.2.2")
    winame="wazuh"
    tarfile=/tmp/tarfile.tar
    @mock tar -axf "${tar_file}" ./clusterkey -O === @out 68b6975cf186649490e2afbc6230c317
    @mock cut -d : -f 1
    @mock grep -n "<cluster>" /var/ossec/etc/ossec.conf === @out 1
    @mock grep -n "</cluster>" /var/ossec/etc/ossec.conf === @out 20
    @mocktrue sed -i -e "1,20s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/"  -e  "1,20s/<node_name>.*<\/node_name>/<node_name>wazuh<\/node_name>/"  -e  "1,20s/<node_type>.*<\/node_type>/<node_type>master<\/node_type>/"  -e  "1,20s/<key>.*<\/key>/<key>68b6975cf186649490e2afbc6230c317<\/key>/"  -e  "1,20s/<port>.*<\/port>/<port>1516<\/port>/"  -e  "1,20s/<bind_addr>.*<\/bind_addr>/<bind_addr>0.0.0.0<\/bind_addr>/"  -e  "1,20s/<node>.*<\/node>/<node>1.1.1.1<\/node>/"  -e  "1,20s/<hidden>.*<\/hidden>/<hidden>no<\/hidden>/"  -e  "1,20s/<disabled>.*<\/disabled>/<disabled>no<\/disabled>/"  /var/ossec/etc/ossec.conf

    manager_startCluster
    @echo $pos
    @echo $master_address
}

test-05-manager_startCluster-assert() {
    @echo 0
    @echo "1.1.1.1"
}
