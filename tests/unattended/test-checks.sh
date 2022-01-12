#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../../"$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/tests/bach.sh

@setup-test {
    @ignore logger
}

function load-checkSystem() {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkSystem
}

test-ASSERT-FAIL-checkSystem-empty() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
}

test-checkSystem-yum() {
    load-checkSystem
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-zypper() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @echo /usr/bin/zypper
    @mock command -v apt-get === @false
    checkSystem
    @echo "$sys_type"
    @echo "$sep"
}

test-checkSystem-zypper-assert() {
    sys_type="zypper"
    sep="-"
    @echo "$sys_type"
    @echo "$sep"
}

test-checkSystem-apt() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-checkNames() {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkNames
}

test-ASSERT-FAIL-checkNames-elastic-kibana-equals() {
    load-checkNames
    einame="node1"
    kiname="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-elastic-wazuh-equals() {
    load-checkNames
    einame="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-kibana-wazuh-equals() {
    load-checkNames
    kiname="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-wazuh-node-name-not-in-config() {
    load-checkNames
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checkNames
}

test-ASSERT-FAIL-checkNames-kibana-node-name-not-in-config() {
    load-checkNames
    kiname="node1"
    kibana_node_names=(kibana node10)
    @mock echo ${kibana_node_names[@]} === @out kibana node10
    @mock grep -w $kiname === @false
    checkNames
}

test-ASSERT-FAIL-checkNames-elasticsearch-node-name-not-in-config() {
    load-checkNames
    einame="node1"
    elasticsearch_node_names=(elasticsearch node10)
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch node10
    @mock grep -w $einame === @false
    checkNames
}

test-checkNames-all-correct-installing-elastic() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    elasticsearch=1
    checkNames
    @assert-success
}

test-checkNames-all-correct-installing-wazuh() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    wazuh=1
    checkNames
    @assert-success
}

test-checkNames-all-correct-installing-kibana() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    kibana=1
    checkNames
    @assert-success
}


function load-checkArch() {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkArch
}

test-checkArch-x86_64() {
    @mock uname -m === @out x86_64
    load-checkArch
    checkArch
    @assert-success
}

test-ASSERT-FAIL-checkArch-empty() {
    @mock uname -m === @out
    load-checkArch
    checkArch
}

test-ASSERT-FAIL-checkArch-i386() {
    @mock uname -m === @out i386
    load-checkArch
    checkArch
}

function load-checkArguments {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-certs-file-present() {
    load-checkArguments
    AIO=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checkArguments
    @rm $tar_file

}

test-ASSERT-FAIL-checkArguments-certificate-creation-certs-file-present() {
    load-checkArguments
    certificates=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checkArguments
    @rm $tar_file
}

test-ASSERT-FAIL-checkArguments-overwrite-with-no-component-installed() {
    load-checkArguments
    overwrite=1
    AIO=
    elasticsearch=
    wazuh=
    kibana=
    checkArguments
}

test-checkArguments-uninstall-no-component-installed() {
    load-checkArguments
    uninstall=1
    elasticsearchinstalled=""
    elastic_remaining_files=""
    wazuhinstalled=""
    wazuh_remaining_files=""
    kibanainstalled=""
    kibana_remaining_files=""
    filebeatinstalled=""
    filebeat_remaining_files=""
    checkArguments
    @assert-success
}

test-ASSERT-FAIL-checkArguments-uninstall-and-aio() {
    load-checkArguments
    uninstall=1
    AIO=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-wazuh() {
    load-checkArguments
    uninstall=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-kibana() {
    load-checkArguments
    uninstall=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-elasticsearch() {
    load-checkArguments
    uninstall=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-elastic () {
    load-checkArguments
    AIO=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-wazuh () {
    load-checkArguments
    AIO=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-kibana () {
    load-checkArguments
    AIO=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-wazuh-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-wazuh-files-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-elastic-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-elastic-files-no-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-kibana-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-kibana-files-no-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-aio-wazuh-installed-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-wazuh-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-wazuh-files-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-wazuh-files-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-elastic-installed-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-elastic-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-elastic-files-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-elastic-files-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-kibana-installed-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-kibana-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-kibana-files-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-kibana-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-checkArguments-install-elastic-already-installed-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-elastic-remaining-files-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-elastic-already-installed-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-elastic-already-installed-overwrite-assert() {
    rollBack elasticsearch
}

test-checkArguments-install-elastic-remaining-files-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-elastic-remaining-files-overwrite-assert() {
    rollBack elasticsearch
}

test-ASSERT-FAIL-checkArguments-install-wazuh-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-wazuh-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-wazuh-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-already-installed-overwrite-assert() {
    rollBack wazuh
}

test-checkArguments-install-wazuh-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-remaining-files-overwrite-assert() {
    rollBack wazuh
}

test-ASSERT-FAIL-checkArguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-already-installed-overwrite-assert() {
    rollBack filebeat
}

test-checkArguments-install-wazuh-filebeat-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-remaining-files-overwrite-assert() {
    rollBack filebeat
}

test-ASSERT-FAIL-checkArguments-install-kibana-already-installed-no-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-kibana-remaining-files-no-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-kibana-already-installed-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-kibana-already-installed-overwrite-assert() {
    rollBack kibana
}

test-checkArguments-install-kibana-remaining-files-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-kibana-remaining-files-overwrite-assert() {
    rollBack kibana
}

function load-checkHealth() {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkHealth
    @mocktrue checkSpecs
}

test-checkHealth-no-argument() {
    load-checkHealth
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-checkHealth-AIO-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    aio=1
    checkHealth
}

test-ASSERT-FAIL-checkHealth-AIO-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    aio=1
    checkHealth
}

test-checkHealth-AIO-2-cores-4gb() {
    load-checkHealth
    cores=2
    ram_gb=3700
    aio=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-checkHealth-elasticsearch-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    elasticsearch=1
    checkHealth
}

test-ASSERT-FAIL-checkHealth-elasticsearch-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    elasticsearch=1
    checkHealth
}

test-checkHealth-elasticsearch-2-cores-3700-ram() {
    load-checkHealth
    cores=2
    ram_gb=3700
    elasticsearch=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-checkHealth-kibana-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    kibana=1
    checkHealth
}

test-ASSERT-FAIL-checkHealth-kibana-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    kibana=1
    checkHealth
}

test-checkHealth-kibana-2-cores-3700-ram() {
    load-checkHealth
    cores=2
    ram_gb=3700
    kibana=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-checkHealth-wazuh-1-core-1700-ram() {
    load-checkHealth
    cores=1
    ram_gb=1700
    wazuh=1
    checkHealth wazuh
}

test-ASSERT-FAIL-checkHealth-wazuh-2-cores-1000-ram() {
    load-checkHealth
    cores=2
    ram_gb=1000
    wazuh=1
    checkHealth wazuh
}

test-checkHealth-wazuh-2-cores-1700-ram() {
    load-checkHealth
    cores=2
    ram_gb=1700
    wazuh=1
    checkHealth wazuh
    @assert-success
}

function load-checkIfInstalled() {
    @load_function "${base_dir}/tests/unattended/checks.sh" checkIfInstalled
}

test-checkIfInstalled-all-installed-yum() {
    load-checkIfInstalled
    sys_type="yum"

    @mocktrue yum list installed
    @mock grep wazuh-manager === @echo wazuh-manager.x86_64  4.3.0-1  @wazuh
    @mkdir /var/ossec
    @mock echo  wazuh-manager.x86_64  4.3.0-1  @wazuh === @out 4.3.0-1
    @mock awk '{print $2}'

    @mock grep opendistroforelasticsearch === @echo wazuh-manager.x86_64  4.3.0-1  @wazuh
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/elasticsearch
    @mkdir /etc/elasticsearch
    @mock echo  wazuh-manager.x86_64  4.3.0-1  @wazuh === @out 4.3.0-1
    @mock awk '{print $2}'

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuhversion
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $elasticsearchinstalled
    @echo $odversion
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/elasticsearch
    @rmdir /etc/elasticsearch

}

test-checkIfInstalled-all-installed-yum-assert() {
    @echo "wazuh-manager.x86_64 4.3.0-1 @wazuh"
    @echo "4.3.0-1"
    @echo 1

    @echo "wazuh-manager.x86_64 4.3.0-1 @wazuh"
    @echo "4.3.0-1"
    @echo 1
}