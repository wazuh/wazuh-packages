#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
}

function load-checks_system() {
    @load_function "${base_dir}/checks.sh" checks_system
}

test-ASSERT-FAIL-01-checks_system-empty() {
    load-checks_system
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checks_system
}

test-02-checks_system-yum() {
    load-checks_system
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checks_system
    echo "$sys_type"
    echo "$sep"
}

test-02-checks_system-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}

test-03-checks_system-zypper() {
    load-checks_system
    @mock command -v yum === @false
    @mock command -v zypper === @echo /usr/bin/zypper
    @mock command -v apt-get === @false
    checks_system
    @echo "$sys_type"
    @echo "$sep"
}

test-03-checks_system-zypper-assert() {
    sys_type="zypper"
    sep="-"
    @echo "$sys_type"
    @echo "$sep"
}

test-04-checks_system-apt() {
    load-checks_system
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    checks_system
    echo "$sys_type"
    echo "$sep"
}

test-04-checks_system-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-checks_names() {
    @load_function "${base_dir}/checks.sh" checks_names
}

test-ASSERT-FAIL-05-checks_names-elastic-kibana-equals() {
    load-checks_names
    einame="node1"
    kiname="node1"
    checks_names
}

test-ASSERT-FAIL-06-checks_names-elastic-wazuh-equals() {
    load-checks_names
    einame="node1"
    winame="node1"
    checks_names
}

test-ASSERT-FAIL-07-checks_names-kibana-wazuh-equals() {
    load-checks_names
    kiname="node1"
    winame="node1"
    checks_names
}

test-ASSERT-FAIL-08-checks_names-wazuh-node-name-not-in-config() {
    load-checks_names
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checks_names
}

test-ASSERT-FAIL-09-checks_names-kibana-node-name-not-in-config() {
    load-checks_names
    kiname="node1"
    kibana_node_names=(kibana node10)
    @mock echo ${kibana_node_names[@]} === @out kibana node10
    @mock grep -w $kiname === @false
    checks_names
}

test-ASSERT-FAIL-10-checks_names-elasticsearch-node-name-not-in-config() {
    load-checks_names
    einame="node1"
    indexer_node_names=(elasticsearch node10)
    @mock echo ${indexer_node_names[@]} === @out elasticsearch node10
    @mock grep -w $einame === @false
    checks_names
}

test-11-checks_names-all-correct-installing-elastic() {
    load-checks_names
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    indexer_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    elasticsearch=1
    @mock echo ${indexer_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checks_names
    @assert-success
}

test-12-checks_names-all-correct-installing-wazuh() {
    load-checks_names
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    indexer_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    wazuh=1
    @mock echo ${indexer_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checks_names
    @assert-success
}

test-13-checks_names-all-correct-installing-kibana() {
    load-checks_names
    einame="elasticsearch1"
    kiname="kibana1"
    winame="wazuh1"
    indexer_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    kibana=1
    @mock echo ${indexer_node_names[@]} === @out elasticsearch1 node1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $einame
    @mock grep -w $winame
    @mock grep -w $kiname
    checks_names
    @assert-success
}


function load-checks_arch() {
    @load_function "${base_dir}/checks.sh" checks_arch
}

test-14-checks_arch-x86_64() {
    @mock uname -m === @out x86_64
    load-checks_arch
    checks_arch
    @assert-success
}

test-ASSERT-FAIL-15-checks_arch-empty() {
    @mock uname -m === @out
    load-checks_arch
    checks_arch
}

test-ASSERT-FAIL-16-checks_arch-i386() {
    @mock uname -m === @out i386
    load-checks_arch
    checks_arch
}

function load-checks_arguments {
    @load_function "${base_dir}/checks.sh" checks_arguments
}

test-ASSERT-FAIL-17-checks_arguments-install-aio-certs-file-present() {
    load-checks_arguments
    AIO=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checks_arguments
    @rm $tar_file

}

test-ASSERT-FAIL-18-checks_arguments-certificate-creation-certs-file-present() {
    load-checks_arguments
    certificates=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checks_arguments
    @rm $tar_file
}

test-ASSERT-FAIL-19-checks_arguments-overwrite-with-no-component-installed() {
    load-checks_arguments
    overwrite=1
    AIO=
    elasticsearch=
    wazuh=
    kibana=
    checks_arguments
}

test-20-checks_arguments-uninstall-no-component-installed() {
    load-checks_arguments
    uninstall=1
    indexerchinstalled=""
    elastic_remaining_files=""
    wazuhinstalled=""
    wazuh_remaining_files=""
    kibanainstalled=""
    kibana_remaining_files=""
    filebeatinstalled=""
    filebeat_remaining_files=""
    checks_arguments
    @assert-success
}

test-ASSERT-FAIL-21-checks_arguments-uninstall-and-aio() {
    load-checks_arguments
    uninstall=1
    AIO=1
    checks_arguments
}

test-ASSERT-FAIL-22-checks_arguments-uninstall-and-wazuh() {
    load-checks_arguments
    uninstall=1
    wazuh=1
    checks_arguments
}

test-ASSERT-FAIL-23-checks_arguments-uninstall-and-kibana() {
    load-checks_arguments
    uninstall=1
    kibana=1
    checks_arguments
}

test-ASSERT-FAIL-24-checks_arguments-uninstall-and-elasticsearch() {
    load-checks_arguments
    uninstall=1
    elasticsearch=1
    checks_arguments
}

test-ASSERT-FAIL-25-checks_arguments-install-aio-and-elastic () {
    load-checks_arguments
    AIO=1
    elasticsearch=1
    checks_arguments
}

test-ASSERT-FAIL-26-checks_arguments-install-aio-and-wazuh () {
    load-checks_arguments
    AIO=1
    wazuh=1
    checks_arguments
}

test-ASSERT-FAIL-27-checks_arguments-install-aio-and-kibana () {
    load-checks_arguments
    AIO=1
    kibana=1
    checks_arguments
}

test-ASSERT-FAIL-28-checks_arguments-install-aio-wazuh-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    wazuhinstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-29-checks_arguments-install-aio-wazuh-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-30-checks_arguments-install-aio-elastic-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    indexerchinstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-31-checks_arguments-install-aio-elastic-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    elastic_remaining_files=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-32-checks_arguments-install-aio-kibana-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    kibanainstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-33-checks_arguments-install-aio-kibana-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    kibana_remaining_files=1
    overwrite=
    checks_arguments
}

test-34-checks_arguments-install-aio-wazuh-installed-overwrite() {
    load-checks_arguments
    AIO=1
    wazuhinstalled=1
    overwrite=1
    checks_arguments
}

test-34-checks_arguments-install-aio-wazuh-installed-overwrite-assert() {
    common_rollBack
}

test-35-checks_arguments-install-aio-wazuh-files-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checks_arguments
}

test-35-checks_arguments-install-aio-wazuh-files-overwrite-assert() {
    common_rollBack
}

test-36-checks_arguments-install-aio-elastic-installed-overwrite() {
    load-checks_arguments
    AIO=1
    indexerchinstalled=1
    overwrite=1
    checks_arguments
}

test-36-checks_arguments-install-aio-elastic-installed-overwrite-assert() {
    common_rollBack
}

test-37-checks_arguments-install-aio-elastic-files-overwrite() {
    load-checks_arguments
    AIO=1
    elastic_remaining_files=1
    overwrite=1
    checks_arguments
}

test-37-checks_arguments-install-aio-elastic-files-overwrite-assert() {
    common_rollBack
}

test-38-checks_arguments-install-aio-kibana-installed-overwrite() {
    load-checks_arguments
    AIO=1
    kibanainstalled=1
    overwrite=1
    checks_arguments
}

test-38-checks_arguments-install-aio-kibana-installed-overwrite-assert() {
    common_rollBack
}

test-39-checks_arguments-install-aio-kibana-files-overwrite() {
    load-checks_arguments
    AIO=1
    kibana_remaining_files=1
    overwrite=1
    checks_arguments
}

test-39-checks_arguments-install-aio-kibana-files-overwrite-assert() {
    common_rollBack
}

test-ASSERT-FAIL-40-checks_arguments-install-elastic-already-installed-no-overwrite() {
    load-checks_arguments
    elasticsearch=1
    indexerchinstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-41-checks_arguments-install-elastic-remaining-files-no-overwrite() {
    load-checks_arguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=
    checks_arguments
}

test-42-checks_arguments-install-elastic-already-installed-overwrite() {
    load-checks_arguments
    elasticsearch=1
    indexerchinstalled=1
    overwrite=1
    checks_arguments
}

test-42-checks_arguments-install-elastic-already-installed-overwrite-assert() {
    common_rollBack
}

test-43-checks_arguments-install-elastic-remaining-files-overwrite() {
    load-checks_arguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=1
    checks_arguments
}

test-43-checks_arguments-install-elastic-remaining-files-overwrite-assert() {
    common_rollBack
}

test-ASSERT-FAIL-44-checks_arguments-install-wazuh-already-installed-no-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuhinstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-45-checks_arguments-install-wazuh-remaining-files-no-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=
    checks_arguments
}

test-46-checks_arguments-install-wazuh-already-installed-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuhinstalled=1
    overwrite=1
    checks_arguments
}

test-46-checks_arguments-install-wazuh-already-installed-overwrite-assert() {
    common_rollBack
}

test-47-checks_arguments-install-wazuh-remaining-files-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checks_arguments
}

test-47-checks_arguments-install-wazuh-remaining-files-overwrite-assert() {
    common_rollBack
}

test-ASSERT-FAIL-48-checks_arguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeatinstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-49-checks_arguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=
    checks_arguments
}

test-50-checks_arguments-install-wazuh-filebeat-already-installed-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeatinstalled=1
    overwrite=1
    checks_arguments
}

test-50-checks_arguments-install-wazuh-filebeat-already-installed-overwrite-assert() {
    common_rollBack
}

test-51-checks_arguments-install-wazuh-filebeat-remaining-files-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checks_arguments
}

test-51-checks_arguments-install-wazuh-filebeat-remaining-files-overwrite-assert() {
    common_rollBack
}

test-ASSERT-FAIL-52-checks_arguments-install-kibana-already-installed-no-overwrite() {
    load-checks_arguments
    kibana=1
    kibanainstalled=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-53-checks_arguments-install-kibana-remaining-files-no-overwrite() {
    load-checks_arguments
    kibana=1
    kibana_remaining_files=1
    overwrite=
    checks_arguments
}

test-54-checks_arguments-install-kibana-already-installed-overwrite() {
    load-checks_arguments
    kibana=1
    kibanainstalled=1
    overwrite=1
    checks_arguments
}

test-54-checks_arguments-install-kibana-already-installed-overwrite-assert() {
    common_rollBack
}

test-55-checks_arguments-install-kibana-remaining-files-overwrite() {
    load-checks_arguments
    kibana=1
    kibana_remaining_files=1
    overwrite=1
    checks_arguments
}

test-55-checks_arguments-install-kibana-remaining-files-overwrite-assert() {
    common_rollBack
}

function load-checks_health() {
    @load_function "${base_dir}/checks.sh" checks_health
    @mocktrue checks_specifications
}

test-56-checks_health-no-installation() {
    load-checks_health
    checks_health
    @assert-success
}

test-ASSERT-FAIL-57-checks_health-AIO-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    aio=1
    checks_health
}

test-ASSERT-FAIL-58-checks_health-AIO-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    aio=1
    checks_health
}

test-59-checks_health-AIO-2-cores-4gb() {
    load-checks_health
    cores=2
    ram_gb=3700
    aio=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-60-checks_health-elasticsearch-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    elasticsearch=1
    checks_health
}

test-ASSERT-FAIL-61-checks_health-elasticsearch-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    elasticsearch=1
    checks_health
}

test-62-checks_health-elasticsearch-2-cores-3700-ram() {
    load-checks_health
    cores=2
    ram_gb=3700
    elasticsearch=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-63-checks_health-kibana-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    kibana=1
    checks_health
}

test-ASSERT-FAIL-64-checks_health-kibana-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    kibana=1
    checks_health
}

test-65-checks_health-kibana-2-cores-3700-ram() {
    load-checks_health
    cores=2
    ram_gb=3700
    kibana=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-66-checks_health-wazuh-1-core-1700-ram() {
    load-checks_health
    cores=1
    ram_gb=1700
    wazuh=1
    checks_health
}

test-ASSERT-FAIL-67-checks_health-wazuh-2-cores-1000-ram() {
    load-checks_health
    cores=2
    ram_gb=1000
    wazuh=1
    checks_health
}

test-68-checks_health-wazuh-2-cores-1700-ram() {
    load-checks_health
    cores=2
    ram_gb=1700
    wazuh=1
    checks_health
    @assert-success
}

function load-checks_installed() {
    @load_function "${base_dir}/checks.sh" checks_installed
}

test-69-checks_installed-all-installed-yum() {
    load-checks_installed
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager === @echo wazuh-manager.x86_64  4.3.0-1  @wazuh
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/wazuh-indexer
    @mkdir /etc/wazuh-indexer

    @mock grep filebeat === @echo filebeat.x86_64 7.10.2-1 @wazuh
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana.x86_64
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $indexerchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/wazuh-indexer
    @rmdir /etc/wazuh-indexer

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

test-69-checks_installed-all-installed-yum-assert() {
    @echo "wazuh-manager.x86_64 4.3.0-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh"
    @echo 1

    @echo "filebeat.x86_64 7.10.2-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch-kibana.x86_64"
    @echo 1
}

test-70-checks_installed-all-installed-zypper() {
    load-checks_installed
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager === @echo "i+ | EL-20211102 - Wazuh | wazuh-manager | 4.3.0-1 | x86_64"
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/wazuh-indexer
    @mkdir /etc/wazuh-indexer

    @mock grep filebeat === @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $indexerchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/wazuh-indexer
    @rmdir /etc/wazuh-indexer

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

test-70-checks_installed-all-installed-zypper-assert() {
    @echo "i+ | EL-20211102 - Wazuh | wazuh-manager | 4.3.0-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
    @echo 1
}

test-71-checks_installed-all-installed-apt() {
    load-checks_installed
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager === @echo wazuh-manager/now 4.2.5-1 amd64 [installed,local]
    @mkdir /var/ossec

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]
    @mock grep -v kibana
    @mkdir /var/lib/elasticsearch/
    @mkdir /usr/share/wazuh-indexer
    @mkdir /etc/wazuh-indexer

    @mock grep filebeat === @echo filebeat/now 7.10.2 amd64 [installed,local]
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]
    @mkdir /var/lib/kibana/
    @mkdir /usr/share/kibana
    @mkdir /etc/kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files
    @rmdir /var/ossec

    @echo $indexerchinstalled
    @echo $elastic_remaining_files
    @rmdir /var/lib/elasticsearch/
    @rmdir /usr/share/wazuh-indexer
    @rmdir /etc/wazuh-indexer

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

test-71-checks_installed-all-installed-apt-assert() {
    @echo "wazuh-manager/now 4.2.5-1 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]"
    @echo 1

    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]"
    @echo 1
}

test-72-checks_installed-nothing-installed-apt() {
    load-checks_installed
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-72-checks_installed-nothing-installed-apt-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-73-checks_installed-nothing-installed-yum() {
    load-checks_installed
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-73-checks_installed-nothing-installed-yum-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-74-checks_installed-nothing-installed-zypper() {
    load-checks_installed
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    checks_installed
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-74-checks_installed-nothing-installed-zypper-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

function load-checks_previousCertificate() {
    @load_function "${base_dir}/checks.sh" checks_previousCertificate
}

test-ASSERT-FAIL-75-checks_previousCertificate-no-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    if [ -f $tar_file ]; then
        @rm $tar_file
    fi
    checks_previousCertificate
}

test-ASSERT-FAIL-76-checks_previousCertificate-einame-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    einame="elastic1"
    @mockfalse grep -q elastic1.pem
    @mockfalse grep -q elastic1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-77-checks_previousCertificate-kiname-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    kiname="kibana1"
    @mockfalse grep -q kibana1.pem
    @mockfalse grep -q kibana1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-78-checks_previousCertificate-winame-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    winame="wazuh1"
    @mockfalse grep -q wazuh1.pem
    @mockfalse grep -q wazuh1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-79-checks_previousCertificate-all-correct() {
    load-checks_previousCertificate
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
    checks_previousCertificate
    @assert-success
    @rm /tmp/tarfile.tar
}