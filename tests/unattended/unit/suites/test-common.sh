#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-common_checkSystem() {
    @load_function "${base_dir}/common.sh" common_checkSystem
}

test-ASSERT-FAIL-01-common_checkSystem-empty() {
    load-common_checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    common_checkSystem
}

test-02-common_checkSystem-yum() {
    load-common_checkSystem
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    common_checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-02-common_checkSystem-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}

test-03-common_checkSystem-zypper() {
    load-common_checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @echo /usr/bin/zypper
    @mock command -v apt-get === @false
    common_checkSystem
    @echo "$sys_type"
    @echo "$sep"
}

test-03-common_checkSystem-zypper-assert() {
    sys_type="zypper"
    sep="-"
    @echo "$sys_type"
    @echo "$sep"
}

test-04-common_checkSystem-apt() {
    load-common_checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    common_checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-04-common_checkSystem-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-common_checkInstalled() {
    @load_function "${base_dir}/common.sh" common_checkInstalled
}

test-69-common_checkInstalled-all-installed-yum() {
    load-common_checkInstalled
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

    common_checkInstalled
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

test-69-common_checkInstalled-all-installed-yum-assert() {
    @echo "wazuh-manager.x86_64 4.3.0-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh"
    @echo 1

    @echo "filebeat.x86_64 7.10.2-1 @wazuh"
    @echo 1

    @echo "opendistroforelasticsearch-kibana.x86_64"
    @echo 1
}

test-70-common_checkInstalled-all-installed-zypper() {
    load-common_checkInstalled
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

    common_checkInstalled
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

test-70-common_checkInstalled-all-installed-zypper-assert() {
    @echo "i+ | EL-20211102 - Wazuh | wazuh-manager | 4.3.0-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @echo 1

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
    @echo 1
}

test-71-common_checkInstalled-all-installed-apt() {
    load-common_checkInstalled
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

    common_checkInstalled
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

test-71-common_checkInstalled-all-installed-apt-assert() {
    @echo "wazuh-manager/now 4.2.5-1 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]"
    @echo 1

    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo 1

    @echo "opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]"
    @echo 1
}

test-72-common_checkInstalled-nothing-installed-apt() {
    load-common_checkInstalled
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    common_checkInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-72-common_checkInstalled-nothing-installed-apt-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-73-common_checkInstalled-nothing-installed-yum() {
    load-common_checkInstalled
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    common_checkInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-73-common_checkInstalled-nothing-installed-yum-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-74-common_checkInstalled-nothing-installed-zypper() {
    load-common_checkInstalled
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    common_checkInstalled
    @echo $wazuhinstalled
    @echo $wazuh_remaining_files

    @echo $indexerchinstalled
    @echo $elastic_remaining_files

    @echo $filebeatinstalled
    @echo $filebeat_remaining_files

    @echo $kibanainstalled
    @echo $kibana_remaining_files
}

test-74-common_checkInstalled-nothing-installed-zypper-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}