#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
    e_certs_path="/etc/wazuh-indexer/certs/"
}

function load-copyCertificatesIndexer() {
    @load_function "${base_dir}/indexer.sh" copyCertificatesIndexer
}

test-ASSERT-FAIL-01-copyCertificatesIndexer-no-tarfile() {
    load-copyCertificatesIndexer
    tar_file=/tmp/tarfile.tar
    if [ -f ${tar_file} ]; then
        @rm ${tar_file}
    fi
    copyCertificatesIndexer
}

test-02-copyCertificatesIndexer() {
    load-copyCertificatesIndexer
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    pos=0
    indexer_node_names=("elastic1" "elastic2")
    debug=
    copyCertificatesIndexer
}

test-02-copyCertificatesIndexer-assert() {
    mkdir -p /etc/wazuh-indexer/certs/
    tar -xf /tmp/tarfile.tar -C /etc/wazuh-indexer/certs/ ./elastic1.pem  && mv /etc/wazuh-indexer/certs/elastic1.pem /etc/wazuh-indexer/certs/indexer.pem
    tar -xf /tmp/tarfile.tar -C /etc/wazuh-indexer/certs/ ./elastic1-key.pem  && mv /etc/wazuh-indexer/certs/elastic1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    tar -xf /tmp/tarfile.tar -C /etc/wazuh-indexer/certs/ ./root-ca.pem
    tar -xf /tmp/tarfile.tar -C /etc/wazuh-indexer/certs/ ./admin.pem
    tar -xf /tmp/tarfile.tar -C /etc/wazuh-indexer/certs/ ./admin-key.pem
}

function load-installIndexer() {
    @load_function "${base_dir}/indexer.sh" installIndexer
}

test-03-installIndexer-zypper() {
    load-installIndexer
    sys_type="zypper"
    opendistro_version="1.13.2"
    opendistro_revision="1"
    installIndexer
}

test-03-installIndexer-zypper-assert() {
    zypper -n install opendistroforelasticsearch=1.13.2-1
}

test-ASSERT-FAIL-04-installIndexer-zypper-error() {
    load-installIndexer
    sys_type="zypper"
    opendistro_version="1.13.2"
    opendistro_revision="1"
    @mockfalse zypper -n install opendistroforelasticsearch=1.13.2-1
    installIndexer
}

test-05-installIndexer-yum() {
    load-installIndexer
    sys_type="yum"
    sep="-"
    opendistro_version="1.13.2"
    opendistro_revision="1"
    installIndexer
}

test-05-installIndexer-yum-assert() {
    yum install opendistroforelasticsearch-1.13.2-1 -y
}

test-ASSERT-FAIL-06-installIndexer-yum-error() {
    load-installIndexer
    sys_type="yum"
    sep="-"
    opendistro_version="1.13.2"
    opendistro_revision="1"
    @mockfalse yum install opendistroforelasticsearch-1.13.2-1 -y 
    installIndexer
}

test-07-installIndexer-apt() {
    load-installIndexer
    sys_type="apt-get"
    sep="="
    opendistro_version="1.13.2"
    opendistro_revision="1"
    installIndexer
}

test-07-installIndexer-apt-assert() {
    apt install elasticsearch-oss opendistroforelasticsearch -y 
}

test-ASSERT-FAIL-08-installIndexer-apt-error() {
    load-installIndexer
    sys_type="apt-get"
    sep="="
    opendistro_version="1.13.2"
    opendistro_revision="1"
    @mockfalse apt install elasticsearch-oss opendistroforelasticsearch -y 
    installIndexer
}

function load-configureIndexer() {
    @load_function "${base_dir}/indexer.sh" configureIndexer
}

test-09-configureIndexer-dist-one-elastic-node() {
    load-configureIndexer
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    @mocktrue free -g
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0
    einame="elastic1"
    configureIndexer
}

test-09-configureIndexer-dist-one-elastic-node-assert() {
    common_getConfig elasticsearch/roles/roles.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles.yml
    common_getConfig elasticsearch/roles/roles_mapping.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles_mapping.yml
    common_getConfig elasticsearch/roles/internal_users.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml

    rm -f /etc/wazuh-indexer/esnode-key.pem /etc/wazuh-indexer/esnode.pem /etc/wazuh-indexer/kirk-key.pem /etc/wazuh-indexer/kirk.pem /etc/wazuh-indexer/root-ca.pem 
    copyCertificatesIndexer

    sed -i "s/-Xms1g/-Xms1g/" /etc/wazuh-indexer/jvm.options
    sed -i "s/-Xmx1g/-Xmx1g/" /etc/wazuh-indexer/jvm.options

    common_getConfig elasticsearch/elasticsearch_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml

    applyLog4j2Mitigation

    /usr/share/wazuh-indexer/bin/opensearch-plugin remove opendistro-performance-analyzer
    rm /etc/wazuh-indexer/certs/client-certificates.readme /etc/wazuh-indexer/certs/elasticsearch_elasticsearch_config_snippet.yml -f

}

test-10-configureIndexer-dist-two-elastic-nodes() {
    load-configureIndexer
    indexer_node_names=("elastic1" "elastic2")
    indexer_node_ips=("1.1.1.1", "1.1.2.2")
    @mock free -g === @out "1"
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0
    einame="elastic2"
    configureIndexer
}

test-10-configureIndexer-dist-two-elastic-nodes-assert() {
    common_getConfig elasticsearch/roles/roles.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles.yml
    common_getConfig elasticsearch/roles/roles_mapping.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles_mapping.yml
    common_getConfig elasticsearch/roles/internal_users.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml

    rm -f /etc/wazuh-indexer/esnode-key.pem /etc/wazuh-indexer/esnode.pem /etc/wazuh-indexer/kirk-key.pem /etc/wazuh-indexer/kirk.pem /etc/wazuh-indexer/root-ca.pem
    copyCertificatesIndexer

    sed -i "s/-Xms1g/-Xms1g/" /etc/wazuh-indexer/jvm.options
    sed -i "s/-Xmx1g/-Xmx1g/" /etc/wazuh-indexer/jvm.options

    common_getConfig elasticsearch/elasticsearch_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml

    applyLog4j2Mitigation

    /usr/share/wazuh-indexer/bin/opensearch-plugin remove opendistro-performance-analyzer
    rm /etc/wazuh-indexer/certs/client-certificates.readme /etc/wazuh-indexer/certs/elasticsearch_elasticsearch_config_snippet.yml -f
}

test-11-configureIndexer-AIO() {
    load-configureIndexer
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    @mock free -g === @out "1"
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0

    configureIndexer
}

test-11-configureIndexer-AIO-assert() {
    common_getConfig elasticsearch/roles/roles.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles.yml
    common_getConfig elasticsearch/roles/roles_mapping.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles_mapping.yml
    common_getConfig elasticsearch/roles/internal_users.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml
    
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
    rm -f /etc/wazuh-indexer/esnode-key.pem /etc/wazuh-indexer/esnode.pem /etc/wazuh-indexer/kirk-key.pem /etc/wazuh-indexer/kirk.pem /etc/wazuh-indexer/root-ca.pem

    copyCertificatesIndexer

    sed -i 's/-Xms1g/-Xms1g/' /etc/wazuh-indexer/jvm.options
    sed -i 's/-Xmx1g/-Xmx1g/' /etc/wazuh-indexer/jvm.options

    common_getConfig elasticsearch/elasticsearch_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml

    applyLog4j2Mitigation

    rm /etc/wazuh-indexer/certs/client-certificates.readme /etc/wazuh-indexer/certs/elasticsearch_elasticsearch_config_snippet.yml -f

}

function load-initializeIndexer() {
    @load_function "${base_dir}/indexer.sh" initializeIndexer
}

test-12-initializeIndexer-one-node() {
    load-initializeIndexer
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    pos=0
    @mocktrue curl -XGET https://1.1.1.1:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    initializeIndexer
    @echo ${start_elastic_cluster}
}

test-12-initializeIndexer-one-node-assert() {
    startIndexerCluster
    common_changePasswords
    @echo 1
}

test-13-initializeIndexer-two-nodes() {
    load-initializeIndexer
    indexer_node_names=("elastic1" "elastic2")
    indexer_node_ips=("1.1.1.1" "1.1.2.2")
    pos=1
    @mocktrue curl -XGET https://1.1.2.2:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    initializeIndexer
    @assert-success
}

test-ASSERT-FAIL-14-initializeIndexer-error-connecting() {
    load-initializeIndexer
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    pos=0
    @mockfalse curl -XGET https://1.1.1.1:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    initializeIndexer
}

function load-applyLog4j2Mitigation() {
    @load_function "${base_dir}/indexer.sh" applyLog4j2Mitigation
}

test-15-applyLog4j2Mitigation() {
    load-applyLog4j2Mitigation
    applyLog4j2Mitigation
}

test-15-applyLog4j2Mitigation-assert() {
    curl -so /tmp/apache-log4j-2.17.1-bin.tar.gz https://packages.wazuh.com/utils/log4j/apache-log4j-2.17.1-bin.tar.gz
    tar -xf /tmp/apache-log4j-2.17.1-bin.tar.gz -C /tmp/

    cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/wazuh-indexer/lib/
    cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/wazuh-indexer/lib/
    cp /tmp/apache-log4j-2.17.1-bin/log4j-slf4j-impl-2.17.1.jar /usr/share/wazuh-indexer/plugins/opensearch-security/
    cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/wazuh-indexer/performance-analyzer-rca/lib/
    cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/wazuh-indexer/performance-analyzer-rca/lib/

    rm -f /usr/share/wazuh-indexer/lib//log4j-api-2.11.1.jar
    rm -f /usr/share/wazuh-indexer/lib/log4j-core-2.11.1.jar
    rm -f /usr/share/wazuh-indexer/plugins/opensearch-security/log4j-slf4j-impl-2.11.1.jar
    rm -f /usr/share/wazuh-indexer/performance-analyzer-rca/lib/log4j-api-2.13.0.jar
    rm -f /usr/share/wazuh-indexer/performance-analyzer-rca/lib/log4j-core-2.13.0.jar

    rm -rf /tmp/apache-log4j-2.17.1-bin
    rm -f /tmp/apache-log4j-2.17.1-bin.tar.gz
}
