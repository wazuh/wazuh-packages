#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
    k_certs_path="/etc/kibana/certs/"
    wazuh_version="4.3.0"
    elasticsearch_oss_version="7.10.2"
    wazuh_kibana_plugin_revision="1"
    repobaseurl="https://packages.wazuh.com/4.x"
    kibana_wazuh_plugin="${repobaseurl}/ui/kibana/wazuh_kibana-${wazuh_version}_${elasticsearch_oss_version}-${wazuh_kibana_plugin_revision}.zip"
}

function load-copyKibanacerts() {
    @load_function "${base_dir}/kibana.sh" copyKibanacerts
}

test-ASSERT-FAIL-copyKibanacerts-no-tarfile() {
    load-copyKibanacerts
    tar_file=/tmp/tarfile.tar
    if [ -f ${tar_file} ]; then
        @rm ${tar_file}
    fi
    copyKibanacerts
}

test-copyKibanacerts() {
    load-copyKibanacerts
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    pos=0
    kibana_node_names=("kibana1" "kibana2")
    debug=
    copyKibanacerts
}

test-copyKibanacerts-assert() {
    mkdir /etc/kibana/certs
    tar -xf /tmp/tarfile.tar -C /etc/kibana/certs/ ./kibana1.pem  && mv /etc/kibana/certs/kibana1.pem /etc/kibana/certs/kibana.pem
    tar -xf /tmp/tarfile.tar -C /etc/kibana/certs/ ./kibana1-key.pem  && mv /etc/kibana/certs/kibana1-key.pem /etc/kibana/certs/kibana-key.pem
    tar -xf /tmp/tarfile.tar -C /etc/kibana/certs/ ./root-ca.pem
    chown -R kibana:kibana /etc/kibana/
    chmod -R 500 /etc/kibana/certs
    chmod 440 /etc/kibana/certs/*
}

function load-installKibana() {
    @load_function "${base_dir}/kibana.sh" installKibana
}

test-installKibana-zypper() {
    load-installKibana
    sys_type="zypper"
    opendistro_version="1.13.2"
    installKibana
}

test-installKibana-zypper-assert() {
    zypper -n install opendistroforelasticsearch-kibana=1.13.2
}

test-ASSERT-FAIL-installKibana-zypper-error() {
    load-installKibana
    sys_type="zypper"
    opendistro_version="1.13.2"
    @mockfalse zypper -n install opendistroforelasticsearch-kibana=1.13.2
    installKibana
}

test-installKibana-yum() {
    load-installKibana
    sys_type="yum"
    sep="-"
    opendistro_version="1.13.2"
    installKibana
}

test-installKibana-yum-assert() {
    yum install opendistroforelasticsearch-kibana-1.13.2 -y 
}

test-ASSERT-FAIL-installKibana-yum-error() {
    load-installKibana
    sys_type="yum"
    sep="-"
    opendistro_version="1.13.2"
    @mockfalse yum install opendistroforelasticsearch-kibana-1.13.2 -y 
    installKibana
}

test-installKibana-apt() {
    load-installKibana
    sys_type="apt-get"
    sep="="
    opendistro_version="1.13.2"
    installKibana
}

test-installKibana-apt-assert() {
    apt-get install opendistroforelasticsearch-kibana=1.13.2 -y 
}

test-ASSERT-FAIL-installKibana-apt-error() {
    load-installKibana
    sys_type="apt-get"
    sep="="
    opendistro_version="1.13.2"
    @mockfalse apt-get install opendistroforelasticsearch-kibana=1.13.2 -y 
    installKibana
}

function load-configureKibana() {
    @load_function "${base_dir}/kibana.sh" configureKibana
}

test-configureKibana-dist-one-kibana-node-one-elastic-node() {
    load-configureKibana
    kibana_node_names=("kibana1")
    kibana_node_ips=("1.1.1.1")
    elasticsearch_node_names=("elastic1")
    elasticsearch_node_names=("1.1.1.1")
    configureKibana
}


test-configureKibana-dist-one-kibana-node-one-elastic-node-assert() {
    getConfig kibana/kibana_unattended_distributed.yml /etc/kibana/kibana.yml
    mkdir /usr/share/kibana/data
    chown -R kibana:kibana /usr/share/kibana/
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.0_7.10.2-1.zip
    setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
    echo 'server.host: "'1.1.1.1'"' >> /etc/kibana/kibana.yml
    echo "elasticsearch.hosts: https://1.1.1.1:9200" >> /etc/kibana/kibana.yml
    modifyKibanaLogin
    copyKibanacerts
}

test-configureKibana-dist-two-kibana-nodes-two-elastic-nodes() {
    load-configureKibana
    kiname="kibana2"
    kibana_node_names=("kibana1" "kibana2")
    kibana_node_ips=("1.1.1.1" "2.2.2.2")
    elasticsearch_node_names=("elastic1" "elastic2")
    elasticsearch_node_names=("1.1.1.1" "2.2.2.2")
    configureKibana
}

test-configureKibana-dist-two-kibana-nodes-two-elastic-nodes-assert() {
    getConfig kibana/kibana_unattended_distributed.yml /etc/kibana/kibana.yml
    mkdir /usr/share/kibana/data
    chown -R kibana:kibana /usr/share/kibana/
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.0_7.10.2-1.zip
    setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
    echo 'server.host: "2.2.2.2"' >> /etc/kibana/kibana.yml
    echo "elasticsearch.hosts:" >> /etc/kibana/kibana.yml
    echo "  - https://1.1.1.1:9200" >> /etc/kibana/kibana.yml
    echo "  - https://2.2.2.2:9200" >> /etc/kibana/kibana.yml
    modifyKibanaLogin
    copyKibanacerts
}

test-ASSERT-FAIL-configureKibana-dist-error-downloading-plugin() {
    load-configureKibana
    @mockfalse sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.0_7.10.2-1.zip
    configureKibana
}

function load-configureKibanaAIO() {
    @load_function "${base_dir}/kibana.sh" configureKibanaAIO
}

test-configureKibana-AIO() {
    load-configureKibanaAIO
    kibana_node_names=("kibana1")
    kibana_node_ips=("1.1.1.1")
    elasticsearch_node_names=("elastic1")
    elasticsearch_node_names=("1.1.1.1")
    configureKibanaAIO
}


test-configureKibana-AIO-assert() {
    getConfig kibana/kibana_unattended.yml /etc/kibana/kibana.yml
    mkdir /usr/share/kibana/data
    chown -R kibana:kibana /usr/share/kibana/
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.0_7.10.2-1.zip
    copyKibanacerts
    setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
    modifyKibanaLogin
}

test-ASSERT-FAIL-configureKibanaAIO-error-downloading-plugin() {
    load-configureKibanaAIO
    @mockfalse sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.0_7.10.2-1.zip
    configureKibanaAIO
}

function load-initializeKibana() {
    @load_function "${base_dir}/kibana.sh" initializeKibana
}

test-initializeKibana-distributed-one-kibana-node-one-wazuh-node-curl-correct() {
    load-initializeKibana
    kibana_node_names=("kibana1")
    kibana_node_ips=("1.1.1.1")
    u_pass="user_password"
    @mock curl -XGET https://1.1.1.1/status -I -uadmin:"${u_pass}" -k -s --max-time 300 === @out "200 OK"
    @mocktrue grep -q "200 OK"
    wazuh_servers_node_names=("wazuh1")
    wazuh_servers_node_ips=("2.2.2.2")
    initializeKibana
}

test-initializeKibana-distributed-one-kibana-node-one-wazuh-node-curl-correct-assert() {
    getPass "admin"
    sed -i 's,url: https://localhost,url: https://2.2.2.2,g' /usr/share/kibana/data/wazuh/config/wazuh.yml
}


test-ASSERT-FAIL-initializeKibana-distributed-one-kibana-node-one-wazuh-node-curl-error() {
    load-initializeKibana
    kibana_node_names=("kibana1")
    kibana_node_ips=("1.1.1.1")
    u_pass="user_password"
    @mock curl -XGET https://1.1.1.1/status -I -uadmin:"${u_pass}" -k -s --max-time 300 === @out "200 OK"
    @mockfalse grep -q "200 OK"
    wazuh_servers_node_names=("wazuh1")
    wazuh_servers_node_ips=("2.2.2.2")
    initializeKibana
}

test-initializeKibana-distributed-two-kibana-nodes-two-wazuh-nodes-curl-correct() {
    load-initializeKibana
    kibana_node_names=("kibana1" "kibana2")
    kibana_node_ips=("1.1.1.1" "1.1.1.2")
    u_pass="user_password"
    @mock curl -XGET https://1.1.1.1/status -I -uadmin:"${u_pass}" -k -s --max-time 300 === @out "200 OK"
    @mocktrue grep -q "200 OK"
    wazuh_servers_node_names=("wazuh1" "wazuh2")
    wazuh_servers_node_types=("worker" "master")
    wazuh_servers_node_ips=("1.1.2.1" "1.1.2.2")
    initializeKibana
}

test-initializeKibana-distributed-two-kibana-nodes-two-wazuh-nodes-curl-correct-assert() {
    getPass "admin"
    sed -i 's,url: https://localhost,url: https://1.1.2.2,g' /usr/share/kibana/data/wazuh/config/wazuh.yml
}

test-ASSERT-FAIL-initializeKibana-distributed-two-kibana-nodes-two-wazuh-nodes-curl-error() {
    load-initializeKibana
    kibana_node_names=("kibana1" "kibana2")
    kibana_node_ips=("1.1.1.1" "1.1.1.2")
    u_pass="user_password"
    @mock curl -XGET https://1.1.2.2/status -I -uadmin:"${u_pass}" -k -s --max-time 300 === @out "200 OK"
    @mockfalse grep -q "200 OK"
    wazuh_servers_node_names=("wazuh1" "wazuh2")
    wazuh_servers_node_types=("worker" "master")
    wazuh_servers_node_ips=("1.1.2.1" "1.1.2.2")
    initializeKibana
}