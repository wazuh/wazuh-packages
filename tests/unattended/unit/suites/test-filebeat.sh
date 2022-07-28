#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
    filebeat_cert_path="/etc/filebeat/certs/"
    wazuh_major="4.3"
    filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
    repobaseurl="https://packages.wazuh.com/4.x"
    filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"
}

function load-filebeat_copyCertificates() {
    @load_function "${base_dir}/filebeat.sh" filebeat_copyCertificates
}

test-ASSERT-FAIL-01-filebeat_copyCertificates-no-tarfile() {
    load-filebeat_copyCertificates
    tar_file=/tmp/tarfile.tar
    if [ -f ${tar_file} ]; then
        @rm ${tar_file}
    fi
    filebeat_copyCertificates
}

test-02-filebeat_copyCertificates-AIO() {
    load-filebeat_copyCertificates
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    AIO=1
    debug=
    filebeat_copyCertificates
}

test-02-filebeat_copyCertificates-AIO-assert() {
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ --wildcards ./filebeat*
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./root-ca.pem
}

test-03-filebeat_copyCertificates-distributed() {
    load-filebeat_copyCertificates
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    AIO=
    debug=
    winame="wazuh1"
    filebeat_copyCertificates
}

test-03-filebeat_copyCertificates-distributed-assert() {
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./wazuh1.pem
    mv /etc/filebeat/certs/wazuh1.pem /etc/filebeat/certs/filebeat.pem
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./wazuh1-key.pem
    mv /etc/filebeat/certs/wazuh1-key.pem /etc/filebeat/certs/filebeat-key.pem
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./root-ca.pem
}

function load-filebeat_install() {
    @load_function "${base_dir}/filebeat.sh" filebeat_install
}

test-04-filebeat_install-yum() {
    load-filebeat_install
    sys_type="yum"
    sep="-"
    filebeat_version="7.10.2"
    filebeat_install
}

test-04-filebeat_install-yum-assert() {
    yum install filebeat-7.10.2 -y -q
}

test-ASSERT-FAIL-05-filebeat_install-yum-error() {
    load-filebeat_install
    sys_type="yum"
    sep="-"
    filebeat_version="7.10.2"
    @mockfalse yum install filebeat-7.10.2 -y -q
    filebeat_install
}

test-06-filebeat_install-apt() {
    load-filebeat_install
    sys_type="apt-get"
    sep="="
    filebeat_version="7.10.2"
    filebeat_install
}

test-06-filebeat_install-apt-assert() {
    apt install filebeat=7.10.2 -y -q
}

test-ASSERT-FAIL-07-filebeat_install-apt-error() {
    load-filebeat_install
    sys_type="apt-get"
    sep="="
    filebeat_version="7.10.2"
    @mockfalse apt install filebeat=7.10.2 -y -q
    filebeat_install
}

function load-filebeat_configure() {
    @load_function "${base_dir}/filebeat.sh" filebeat_configure
}

test-08-filebeat_configure-no-previous-variables() {
    load-filebeat_configure
    filebeat_wazuh_template=""
    filebeat_wazuh_module=""
    @mocktrue curl -s --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    @mocktrue echo admin
    filebeat_configure
}

test-08-filebeat_configure-no-previous-variables-assert() {
    curl -so /etc/filebeat/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    filebeat_copyCertificates
    filebeat keystore create
    filebeat keystore add username --force --stdin
    filebeat keystore add password --force --stdin
}

test-09-filebeat_configure-one-elastic-node() {
    load-filebeat_configure
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    @mocktrue echo admin
    indexer_node_names=("elastic1")
    elasticesarch_node_ips=("1.1.1.1")
    filebeat_configure
}

test-09-filebeat_configure-one-elastic-node-assert() {
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    echo "  - 1.1.1.1" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    filebeat_copyCertificates
    filebeat keystore create
    filebeat keystore add username --force --stdin
    filebeat keystore add password --force --stdin
}

test-10-filebeat_configure-more-than-one-elastic-node() {
    load-filebeat_configure
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    @mocktrue echo admin
    indexer_node_names=("elastic1" "elastic2")
    elasticesarch_node_ips=("1.1.1.1" "2.2.2.2")
    filebeat_configure
}

test-10-filebeat_configure-more-than-one-elastic-node-assert() {
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    echo "  - 1.1.1.1" >> /etc/filebeat/filebeat.yml
    echo "  - 2.2.2.2" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    filebeat_copyCertificates
    filebeat keystore create
    filebeat keystore add username --force --stdin
    filebeat keystore add password --force --stdin
}

test-11-filebeat_configure-AIO-no-previous-variables() {
    load-filebeat_configure
    filebeat_wazuh_template=""
    filebeat_wazuh_module=""
    @mocktrue curl -s --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    @mocktrue echo admin
    AIO=1
    filebeat_configure
}

test-11-filebeat_configure-AIO-no-previous-variables-assert() {
    curl -so /etc/filebeat/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    installCommon_getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    filebeat_copyCertificates
    filebeat keystore create
    filebeat keystore add username --force --stdin
    filebeat keystore add password --force --stdin
}

test-12-filebeat_configure-AIO() {
    load-filebeat_configure
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    @mocktrue echo admin
    AIO=1
    filebeat_configure
}

test-12-filebeat_configure-AIO-assert() {
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    installCommon_getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    filebeat_copyCertificates
    filebeat keystore create
    filebeat keystore add username --force --stdin
    filebeat keystore add password --force --stdin
}
