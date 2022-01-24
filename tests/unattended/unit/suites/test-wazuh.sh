#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
}

function load-installWazuh() {
    @load_function "${base_dir}/wazuh.sh" installWazuh
}

test-01-installWazuh-zypper-error() {
    load-installWazuh
    sys_type="zypper"
    wazuh_version=1
    wazuh_revision=1
    @mockfalse zypper -n install wazuh-manager=1-1
    installWazuh
}

test-01-installWazuh-zypper-error-assert() {
    rollBack
    exit 1
}

test-02-installWazuh-apt-error() {
    load-installWazuh
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    @mockfalse apt-get install wazuh-manager=1-1 -y
    installWazuh
}

test-02-installWazuh-apt-error-assert() {
    rollBack
    exit 1
}

test-03-installWazuh-yum-error() {
    load-installWazuh
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    @mockfalse yum install wazuh-manager-1-1 -y
    installWazuh
}

test-03-installWazuh-yum-error-assert() {
    rollBack
    exit 1
}

test-04-installWazuh-zypper() {
    load-installWazuh
    sys_type="zypper"
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-04-installWazuh-zypper-assert() {
    zypper -n install wazuh-manager=1-1
    @echo 1
}

test-05-installWazuh-apt() {
    load-installWazuh
    sys_type="apt-get"
    sep="="
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-05-installWazuh-apt-assert() {
    apt-get install wazuh-manager=1-1 -y
    @echo 1
}

test-06-installWazuh-yum() {
    load-installWazuh
    sys_type="yum"
    sep="-"
    wazuh_version=1
    wazuh_revision=1
    installWazuh
    @echo $wazuhinstalled
}

test-06-installWazuh-yum-assert() {
    yum install wazuh-manager-1-1 -y
    @echo 1
}

function load-configureWazuhCluster() {
    @load_function "${base_dir}/wazuh.sh" configureWazuhCluster
}

test-07-configureWazuhCluster() {
    load-configureWazuhCluster
    wazuh_servers_node_names=("wazuh" "node10")
    wazuh_servers_node_types=("master" "worker")
    wazuh_servers_node_ips=("1.1.1.1" "2.2.2.2")
    winame="wazuh"
    tarfile=/tmp/tarfile.tar
    @mock tar -axf "${tar_file}" ./clusterkey -O === @out 68b6975cf186649490e2afbc6230c317
    @mock cut -d : -f 1
    @mock grep -n "<cluster>" /var/ossec/etc/ossec.conf === @out 1
    @mock grep -n "</cluster>" /var/ossec/etc/ossec.conf === @out 20
    @mocktrue sed -i -e "1,20s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/"  -e  "1,20s/<node_name>.*<\/node_name>/<node_name>wazuh<\/node_name>/"  -e  "1,20s/<node_type>.*<\/node_type>/<node_type>master<\/node_type>/"  -e  "1,20s/<key>.*<\/key>/<key>68b6975cf186649490e2afbc6230c317<\/key>/"  -e  "1,20s/<port>.*<\/port>/<port>1516<\/port>/"  -e  "1,20s/<bind_addr>.*<\/bind_addr>/<bind_addr>0.0.0.0<\/bind_addr>/"  -e  "1,20s/<node>.*<\/node>/<node>1.1.1.1<\/node>/"  -e  "1,20s/<hidden>.*<\/hidden>/<hidden>no<\/hidden>/"  -e  "1,20s/<disabled>.*<\/disabled>/<disabled>no<\/disabled>/"  /var/ossec/etc/ossec.conf

    configureWazuhCluster
    @echo $pos
    @echo $master_address
}

test-07-configureWazuhCluster-assert() {
    @echo 0
    @echo "1.1.1.1"
}
