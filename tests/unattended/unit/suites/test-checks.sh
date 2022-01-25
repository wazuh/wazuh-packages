#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
}

function load-checkSystem() {
    @load_function "${base_dir}/checks.sh" checkSystem
}

test-ASSERT-FAIL-01-checkSystem-empty() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
}

test-02-checkSystem-yum() {
    load-checkSystem
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-02-checkSystem-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}

test-03-checkSystem-zypper() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @echo /usr/bin/zypper
    @mock command -v apt-get === @false
    checkSystem
    @echo "$sys_type"
    @echo "$sep"
}

test-03-checkSystem-zypper-assert() {
    sys_type="zypper"
    sep="-"
    @echo "$sys_type"
    @echo "$sep"
}

test-04-checkSystem-apt() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-04-checkSystem-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-checkNames() {
    @load_function "${base_dir}/checks.sh" checkNames
}

test-ASSERT-FAIL-05-checkNames-elastic-kibana-equals() {
    load-checkNames
    einame="node1"
    kiname="node1"
    checkNames
}

test-ASSERT-FAIL-06-checkNames-elastic-wazuh-equals() {
    load-checkNames
    einame="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-07-checkNames-kibana-wazuh-equals() {
    load-checkNames
    kiname="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-08-checkNames-wazuh-node-name-not-in-config() {
    load-checkNames
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checkNames
}

test-ASSERT-FAIL-09-checkNames-kibana-node-name-not-in-config() {
    load-checkNames
    kiname="node1"
    kibana_node_names=(kibana node10)
    @mock echo ${kibana_node_names[@]} === @out kibana node10
    @mock grep -w $kiname === @false
    checkNames
}

test-ASSERT-FAIL-10-checkNames-elasticsearch-node-name-not-in-config() {
    load-checkNames
    einame="node1"
    elasticsearch_node_names=(elasticsearch node10)
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch node10
    @mock grep -w $einame === @false
    checkNames
}

test-11-checkNames-all-correct-installing-elastic() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    elasticsearch=1
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checkNames
    @assert-success
}

test-12-checkNames-all-correct-installing-wazuh() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    wazuh=1
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checkNames
    @assert-success
}

test-13-checkNames-all-correct-installing-kibana() {
    load-checkNames
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    kibana=1
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checkNames
    @assert-success
}


function load-checkArch() {
    @load_function "${base_dir}/checks.sh" checkArch
}

test-14-checkArch-x86_64() {
    @mock uname -m === @out x86_64
    load-checkArch
    checkArch
    @assert-success
}

test-ASSERT-FAIL-15-checkArch-empty() {
    @mock uname -m === @out
    load-checkArch
    checkArch
}

test-ASSERT-FAIL-16-checkArch-i386() {
    @mock uname -m === @out i386
    load-checkArch
    checkArch
}

function load-checkArguments {
    @load_function "${base_dir}/checks.sh" checkArguments
}

test-ASSERT-FAIL-17-checkArguments-install-aio-certs-file-present() {
    load-checkArguments
    AIO=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checkArguments
    @rm $tar_file

}

test-ASSERT-FAIL-18-checkArguments-certificate-creation-certs-file-present() {
    load-checkArguments
    certificates=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checkArguments
    @rm $tar_file
}

test-ASSERT-FAIL-19-checkArguments-overwrite-with-no-component-installed() {
    load-checkArguments
    overwrite=1
    AIO=
    elasticsearch=
    wazuh=
    kibana=
    checkArguments
}

test-20-checkArguments-uninstall-no-component-installed() {
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

test-ASSERT-FAIL-21-checkArguments-uninstall-and-aio() {
    load-checkArguments
    uninstall=1
    AIO=1
    checkArguments
}

test-ASSERT-FAIL-22-checkArguments-uninstall-and-wazuh() {
    load-checkArguments
    uninstall=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-23-checkArguments-uninstall-and-kibana() {
    load-checkArguments
    uninstall=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-24-checkArguments-uninstall-and-elasticsearch() {
    load-checkArguments
    uninstall=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-25-checkArguments-install-aio-and-elastic () {
    load-checkArguments
    AIO=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-26-checkArguments-install-aio-and-wazuh () {
    load-checkArguments
    AIO=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-27-checkArguments-install-aio-and-kibana () {
    load-checkArguments
    AIO=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-28-checkArguments-install-aio-wazuh-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-29-checkArguments-install-aio-wazuh-files-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-30-checkArguments-install-aio-elastic-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-31-checkArguments-install-aio-elastic-files-no-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-32-checkArguments-install-aio-kibana-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-33-checkArguments-install-aio-kibana-files-no-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-34-checkArguments-install-aio-wazuh-installed-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-34-checkArguments-install-aio-wazuh-installed-overwrite-assert() {
    rollBack
}

test-35-checkArguments-install-aio-wazuh-files-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-35-checkArguments-install-aio-wazuh-files-overwrite-assert() {
    rollBack
}

test-36-checkArguments-install-aio-elastic-installed-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-36-checkArguments-install-aio-elastic-installed-overwrite-assert() {
    rollBack
}

test-37-checkArguments-install-aio-elastic-files-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-37-checkArguments-install-aio-elastic-files-overwrite-assert() {
    rollBack
}

test-38-checkArguments-install-aio-kibana-installed-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-38-checkArguments-install-aio-kibana-installed-overwrite-assert() {
    rollBack
}

test-39-checkArguments-install-aio-kibana-files-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-39-checkArguments-install-aio-kibana-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-40-checkArguments-install-elastic-already-installed-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-41-checkArguments-install-elastic-remaining-files-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-42-checkArguments-install-elastic-already-installed-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-42-checkArguments-install-elastic-already-installed-overwrite-assert() {
    rollBack
}

test-43-checkArguments-install-elastic-remaining-files-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-43-checkArguments-install-elastic-remaining-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-44-checkArguments-install-wazuh-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-45-checkArguments-install-wazuh-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-46-checkArguments-install-wazuh-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-46-checkArguments-install-wazuh-already-installed-overwrite-assert() {
    rollBack
}

test-47-checkArguments-install-wazuh-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-47-checkArguments-install-wazuh-remaining-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-48-checkArguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-49-checkArguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=
    checkArguments
}

test-50-checkArguments-install-wazuh-filebeat-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=1
    checkArguments
}

test-50-checkArguments-install-wazuh-filebeat-already-installed-overwrite-assert() {
    rollBack
}

test-51-checkArguments-install-wazuh-filebeat-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checkArguments
}

test-51-checkArguments-install-wazuh-filebeat-remaining-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-52-checkArguments-install-kibana-already-installed-no-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-53-checkArguments-install-kibana-remaining-files-no-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-54-checkArguments-install-kibana-already-installed-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-54-checkArguments-install-kibana-already-installed-overwrite-assert() {
    rollBack
}

test-55-checkArguments-install-kibana-remaining-files-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-55-checkArguments-install-kibana-remaining-files-overwrite-assert() {
    rollBack
}

function load-checkHealth() {
    @load_function "${base_dir}/checks.sh" checkHealth
    @mocktrue checkSpecs
}

test-56-checkHealth-no-installation() {
    load-checkHealth
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-57-checkHealth-AIO-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    aio=1
    checkHealth
}

test-ASSERT-FAIL-58-checkHealth-AIO-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    aio=1
    checkHealth
}

test-59-checkHealth-AIO-2-cores-4gb() {
    load-checkHealth
    cores=2
    ram_gb=3700
    aio=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-60-checkHealth-elasticsearch-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    elasticsearch=1
    checkHealth
}

test-ASSERT-FAIL-61-checkHealth-elasticsearch-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    elasticsearch=1
    checkHealth
}

test-62-checkHealth-elasticsearch-2-cores-3700-ram() {
    load-checkHealth
    cores=2
    ram_gb=3700
    elasticsearch=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-63-checkHealth-kibana-1-core-3700-ram() {
    load-checkHealth
    cores=1
    ram_gb=3700
    kibana=1
    checkHealth
}

test-ASSERT-FAIL-64-checkHealth-kibana-2-cores-3000-ram() {
    load-checkHealth
    cores=2
    ram_gb=3000
    kibana=1
    checkHealth
}

test-65-checkHealth-kibana-2-cores-3700-ram() {
    load-checkHealth
    cores=2
    ram_gb=3700
    kibana=1
    checkHealth
    @assert-success
}

test-ASSERT-FAIL-66-checkHealth-wazuh-1-core-1700-ram() {
    load-checkHealth
    cores=1
    ram_gb=1700
    wazuh=1
    checkHealth
}

test-ASSERT-FAIL-67-checkHealth-wazuh-2-cores-1000-ram() {
    load-checkHealth
    cores=2
    ram_gb=1000
    wazuh=1
    checkHealth
}

test-68-checkHealth-wazuh-2-cores-1700-ram() {
    load-checkHealth
    cores=2
    ram_gb=1700
    wazuh=1
    checkHealth
    @assert-success
}

function load-checkIfInstalled() {
    @load_function "${base_dir}/checks.sh" checkIfInstalled
}

test-69-checkIfInstalled-all-installed-yum() {
    load-checkIfInstalled
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager === @echo wazuh-manager.x86_64  4.3.0-1  @wazuh
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/elasticsearch
    @mkdir /etc/elasticsearch

    @mock grep filebeat === @echo filebeat.x86_64 7.10.2-1 @wazuh
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana.x86_64
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/elasticsearch
    @rmdir /etc/elasticsearch

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files
    @rmdir /var/lib/filebeat/
    @rmdir /usr/share/filebeat
    @rmdir /etc/filebeat

    @echo $kibanainstalled
    @echo $kibana_remaining_files
    @rmdir /var/lib/kibana/
    @rmdir /usr/share/kibana
    @rmdir /etc/kibana

}

test-69-checkIfInstalled-all-installed-yum-assert() {
    @echo "wazuh-manager.x86_64 4.3.0-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh"
    @echo 1

    @echo "filebeat.x86_64 7.10.2-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch-kibana.x86_64"
    @echo 1
}

test-70-checkIfInstalled-all-installed-zypper() {
    load-checkIfInstalled
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager === @echo "i+ | EL-20211102 - Wazuh | wazuh-manager | 4.3.0-1 | x86_64"
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/elasticsearch
    @mkdir /etc/elasticsearch

    @mock grep filebeat === @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/elasticsearch
    @rmdir /etc/elasticsearch

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files
    @rmdir /var/lib/filebeat/
    @rmdir /usr/share/filebeat
    @rmdir /etc/filebeat

    @echo $kibanainstalled
    @echo $kibana_remaining_files
    @rmdir /var/lib/kibana/
    @rmdir /usr/share/kibana
    @rmdir /etc/kibana

}

test-70-checkIfInstalled-all-installed-zypper-assert() {
    @echo "i+ | EL-20211102 - Wazuh | wazuh-manager | 4.3.0-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
    @echo 1
}

test-71-checkIfInstalled-all-installed-apt() {
    load-checkIfInstalled
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager === @echo wazuh-manager/now 4.2.5-1 amd64 [installed,local]
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/elasticsearch
    @mkdir /etc/elasticsearch

    @mock grep filebeat === @echo filebeat/now 7.10.2 amd64 [installed,local]
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/elasticsearch
    @rmdir /etc/elasticsearch

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files
    @rmdir /var/lib/filebeat/
    @rmdir /usr/share/filebeat
    @rmdir /etc/filebeat

    @echo $kibanainstalled
    @echo $kibana_remaining_files
    @rmdir /var/lib/kibana/
    @rmdir /usr/share/kibana
    @rmdir /etc/kibana

}

test-71-checkIfInstalled-all-installed-apt-assert() {
    @echo "wazuh-manager/now 4.2.5-1 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]"
    @echo 1

    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]"
    @echo 1
}

test-72-checkIfInstalled-nothing-installed-apt() {
    load-checkIfInstalled
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-72-checkIfInstalled-nothing-installed-apt-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-73-checkIfInstalled-nothing-installed-yum() {
    load-checkIfInstalled
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-73-checkIfInstalled-nothing-installed-yum-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-74-checkIfInstalled-nothing-installed-zypper() {
    load-checkIfInstalled
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checkIfInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $elasticsearchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-74-checkIfInstalled-nothing-installed-zypper-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

function load-checkPreviousCertificates() {
    @load_function "${base_dir}/checks.sh" checkPreviousCertificates
}

test-ASSERT-FAIL-75-checkPreviousCertificates-no-tar_file() {
    load-checkPreviousCertificates
    tar_file=/tmp/tarfile.tar
    if [ -f $tar_file ]; then
        @rm $tar_file
    fi
    checkPreviousCertificates
}

test-ASSERT-FAIL-76-checkPreviousCertificates-einame-not-in-tar_file() {
    load-checkPreviousCertificates
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    einame="elastic1"
    @mockfalse grep -q elastic1.pem
    @mockfalse grep -q elastic1-key.pem
    checkPreviousCertificates
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-77-checkPreviousCertificates-kiname-not-in-tar_file() {
    load-checkPreviousCertificates
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    kiname="kibana1"
    @mockfalse grep -q kibana1.pem
    @mockfalse grep -q kibana1-key.pem
    checkPreviousCertificates
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-78-checkPreviousCertificates-winame-not-in-tar_file() {
    load-checkPreviousCertificates
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    winame="wazuh1"
    @mockfalse grep -q wazuh1.pem
    @mockfalse grep -q wazuh1-key.pem
    checkPreviousCertificates
    @rm /tmp/tarfile.tar
}

test-79-checkPreviousCertificates-all-correct() {
    load-checkPreviousCertificates
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    einame="elastic1"
    @mocktrue grep -q elastic1.pem
    @mocktrue grep -q elastic1-key.pem
    winame="wazuh1"
    @mocktrue grep -q wazuh1.pem
    @mocktrue grep -q wazuh1-key.pem
    kiname="kibana1"
    @mocktrue grep -q kibana1.pem
    @mocktrue grep -q kibana1-key.pem
    checkPreviousCertificates
    @assert-success
    @rm /tmp/tarfile.tar
}