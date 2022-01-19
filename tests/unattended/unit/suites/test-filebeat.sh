#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
    f_cert_path="/etc/filebeat/certs/"
    wazuh_major="4.3"
    filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_major}/extensions/elasticsearch/7.x/wazuh-template.json"
    repobaseurl="https://packages.wazuh.com/4.x"
    filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.1.tar.gz"
}

function load-copyCertificatesFilebeat() {
    @load_function "${base_dir}/filebeat.sh" copyCertificatesFilebeat
}

test-ASSERT-FAIL-copyCertificatesFilebeat-no-tarfile() {
    load-copyCertificatesFilebeat
    tar_file=/tmp/tarfile.tar
    if [ -f ${tar_file} ]; then
        @rm ${tar_file}
    fi
    copyCertificatesFilebeat
}

test-copyCertificatesFilebeat-AIO() {
    load-copyCertificatesFilebeat
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    AIO=1
    debug=
    copyCertificatesFilebeat
}

test-copyCertificatesFilebeat-AIO-assert() {
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ --wildcards ./filebeat*
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./root-ca.pem
}

test-copyCertificatesFilebeat-distributed() {
    load-copyCertificatesFilebeat
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    AIO=
    debug=
    winame="wazuh1"
    copyCertificatesFilebeat
}

test-copyCertificatesFilebeat-distributed-assert() {
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./wazuh1.pem
    mv /etc/filebeat/certs/wazuh1.pem /etc/filebeat/certs/filebeat.pem
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./wazuh1-key.pem
    mv /etc/filebeat/certs/wazuh1-key.pem /etc/filebeat/certs/filebeat-key.pem
    tar -xf /tmp/tarfile.tar -C /etc/filebeat/certs/ ./root-ca.pem
}

function load-installFilebeat() {
    @load_function "${base_dir}/filebeat.sh" installFilebeat
}

test-installFilebeat-zypper() {
    load-installFilebeat
    sys_type="zypper"
    elasticsearch_oss_version="7.10.2"
    installFilebeat
}

test-installFilebeat-zypper-assert() {
    zypper -n install filebeat-7.10.2
}

test-ASSERT-FAIL-installFilebeat-zypper-error() {
    load-installFilebeat
    sys_type="zypper"
    elasticsearch_oss_version="7.10.2"
    @mockfalse zypper -n install filebeat-7.10.2
    installFilebeat
}

test-installFilebeat-yum() {
    load-installFilebeat
    sys_type="yum"
    sep="-"
    elasticsearch_oss_version="7.10.2"
    installFilebeat
}

test-installFilebeat-yum-assert() {
    yum install filebeat-7.10.2 -y -q
}

test-ASSERT-FAIL-installFilebeat-yum-error() {
    load-installFilebeat
    sys_type="yum"
    sep="-"
    elasticsearch_oss_version="7.10.2"
    @mockfalse yum install filebeat-7.10.2 -y -q
    installFilebeat
}

test-installFilebeat-apt() {
    load-installFilebeat
    sys_type="apt-get"
    sep="="
    elasticsearch_oss_version="7.10.2"
    installFilebeat
}

test-installFilebeat-apt-assert() {
    apt-get install filebeat=7.10.2 -y -q
}

test-ASSERT-FAIL-installFilebeat-apt-error() {
    load-installFilebeat
    sys_type="apt-get"
    sep="="
    elasticsearch_oss_version="7.10.2"
    @mockfalse apt-get install filebeat=7.10.2 -y -q
    installFilebeat
}

function load-configureFilebeat() {
    @load_function "${base_dir}/filebeat.sh" configureFilebeat
}

test-configureFilebeat-no-previous-variables() {
    load-configureFilebeat
    filebeat_wazuh_template=""
    filebeat_wazuh_module=""
    @mocktrue curl -s --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    configureFilebeat
}

test-configureFilebeat-no-previous-variables-assert() {
    getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    copyCertificatesFilebeat
}

test-configureFilebeat-one-elastic-node() {
    load-configureFilebeat
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    elasticsearch_node_names=("elastic1")
    elasticesarch_node_ips=("1.1.1.1")
    configureFilebeat
}

test-configureFilebeat-one-elastic-node-assert() {
    getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    echo "  - 1.1.1.1" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    copyCertificatesFilebeat
}

test-configureFilebeat-more-than-one-elastic-node() {
    load-configureFilebeat
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    elasticsearch_node_names=("elastic1" "elastic2")
    elasticesarch_node_ips=("1.1.1.1" "2.2.2.2")
    configureFilebeat
}

test-configureFilebeat-more-than-one-elastic-node-assert() {
    getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
    echo "  - 1.1.1.1" >> /etc/filebeat/filebeat.yml
    echo "  - 2.2.2.2" >> /etc/filebeat/filebeat.yml
    mkdir /etc/filebeat/certs
    copyCertificatesFilebeat
}

function load-configureFilebeatAIO() {
    @load_function "${base_dir}/filebeat.sh" configureFilebeatAIO
}

test-configureFilebeatAIO-no-previous-variables() {
    load-configureFilebeatAIO
    filebeat_wazuh_template=""
    filebeat_wazuh_module=""
    @mocktrue curl -s --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    configureFilebeatAIO
}

test-configureFilebeatAIO-no-previous-variables-assert() {
    getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    mkdir /etc/filebeat/certs
    copyCertificatesFilebeat
}

test-configureFilebeatAIO() {
    load-configureFilebeatAIO
    @mocktrue curl -s ${filebeat_wazuh_module} --max-time 300
    @mock tar -xvz -C /usr/share/filebeat/module
    configureFilebeatAIO
}

test-configureFilebeatAIO-assert() {
    getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300
    chmod go+r /etc/filebeat/wazuh-template.json
    mkdir /etc/filebeat/certs
    copyCertificatesFilebeat
}
