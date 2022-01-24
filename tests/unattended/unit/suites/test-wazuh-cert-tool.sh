#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger_cert
    debug_cert=
    base_path="/tmp/wazuh-cert-tool"
}

function load-cleanFiles() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" cleanFiles
}

test-1-cleanFiles() {
    load-cleanFiles
    cleanFiles
}

test-1-cleanFiles-assert() {
    rm -f /tmp/wazuh-cert-tool/certs/*.csr
    rm -f /tmp/wazuh-cert-tool/certs/*.srl
    rm -f /tmp/wazuh-cert-tool/certs/*.conf
    rm -f /tmp/wazuh-cert-tool/certs/admin-key-temp.pem
}

function load-checkOpenSSL() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" checkOpenSSL
}

test-2-checkOpenSSL-no-openssl() {
    load-checkOpenSSL
    @mockfalse command -v openssl
    checkOpenSSL
}

test-2-checkOpenSSL-no-openssl-assert() {
    exit 1
}

test-3-checkOpenSSL-correct() {
    load-checkOpenSSL
    @mock command -v openssl === @out "/bin/openssl"
    checkOpenSSL
    @assert-success
}

function load-generateAdmincertificate() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateAdmincertificate
}

test-4-generateAdmincertificate() {
    load-generateAdmincertificate
    generateAdmincertificate
}

test-4-generateAdmincertificate-assert() {
    openssl genrsa -out /tmp/wazuh-cert-tool/certs/admin-key-temp.pem 2048
    openssl pkcs8 -inform PEM -outform PEM -in /tmp/wazuh-cert-tool/certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out /tmp/wazuh-cert-tool/certs/admin-key.pem
    openssl req -new -key /tmp/wazuh-cert-tool/certs/admin-key.pem -out /tmp/wazuh-cert-tool/certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Docu/CN=admin'
    openssl x509 -days 3650 -req -in /tmp/wazuh-cert-tool/certs/admin.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -sha256 -out /tmp/wazuh-cert-tool/certs/admin.pem
}

function load-generateCertificateconfiguration() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateCertificateconfiguration
}

test-5-generateCertificateconfiguration-IP() {
    load-generateCertificateconfiguration
    @mkdir -p /tmp/wazuh-cert-tool/certs
    @touch /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @mock echo 1.1.1.1 === @out ""
    @mock awk '{sub("CN = cname", "CN = wazuh1")}1' "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf"
    @mock awk "{sub(\"IP.1 = cip\", \"IP.1 = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf2"
    @mock grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" === @out "1.1.1.1"
    @mock grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" === @out ""
    @mocktrue cat
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    @rm /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @rmdir /tmp/wazuh-cert-tool/certs
}

test-5-generateCertificateconfiguration-IP-assert() {
    echo "conf"
    echo "conf2"
}

test-6-generateCertificateconfiguration-DNS() {
    load-generateCertificateconfiguration
    @mkdir -p /tmp/wazuh-cert-tool/certs
    @touch /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @mock echo 1.1.1.1 === @out ""
    @mock awk "{sub(\"CN = cname\", \"CN = wazuh1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf"
    @mock awk "{sub(\"CN = cname\", \"CN =  1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf2"
    @mock awk "{sub(\"IP.1 = cip\", \"DNS.1 = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf3"
    @mock grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" === @out ""
    @mock grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" === @out "1.1.1.1"
    @mocktrue cat
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    @rm /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @rmdir /tmp/wazuh-cert-tool/certs
}

test-6-generateCertificateconfiguration-DNS-assert() {
    echo "conf"
    echo "conf2"
    echo "conf3"
}

test-7-generateCertificateconfiguration-error() {
    load-generateCertificateconfiguration
    @mkdir -p /tmp/wazuh-cert-tool/certs
    @touch /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @mock echo 1.1.1.1 === @out ""
    @mock awk "{sub(\"CN = cname\", \"CN = wazuh1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf"
    @mock awk "{sub(\"CN = cname\", \"CN = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf2"
    @mock awk "{sub(\"IP.1 = cip\", \"DNS.1 = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf3"
    @mockfalse grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    @mockfalse grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$"
    @mocktrue cat
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    @rm /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @rmdir /tmp/wazuh-cert-tool/certs
}

test-7-generateCertificateconfiguration-error-assert() {
    echo "conf"
    exit 1
}


function load-generateRootCAcertificate() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateRootCAcertificate
}

test-8-generateRootCAcertificate() {
    load-generateRootCAcertificate
    generateRootCAcertificate
}

test-8-generateRootCAcertificate-assert() {
    openssl req -x509 -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/root-ca.key -out /tmp/wazuh-cert-tool/certs/root-ca.pem -batch -subj '/OU=Docu/O=Wazuh/L=California/' -days 3650
}

function load-generateElasticsearchcertificates() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateElasticsearchcertificates
}

test-9-generateElasticsearchcertificates-no-nodes() {
    load-generateElasticsearchcertificates
    elasticsearch_node_names=()
    generateElasticsearchcertificates
    @assert-success
}

test-10-generateElasticsearchcertificates-two-nodes() {
    load-generateElasticsearchcertificates
    elasticsearch_node_names=("elastic1" "elastic2")
    elasticsearch_node_ips=("1.1.1.1" "1.1.1.2")
    generateElasticsearchcertificates
}

test-10-generateElasticsearchcertificates-two-nodes-assert() {
    generateCertificateconfiguration elastic1 1.1.1.1
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/elastic1-key.pem -out /tmp/wazuh-cert-tool/certs/elastic1.csr -config /tmp/wazuh-cert-tool/certs/elastic1.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/elastic1.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/elastic1.pem -extfile /tmp/wazuh-cert-tool/certs/elastic1.conf -extensions v3_req -days 3650
    chmod 444 /tmp/wazuh-cert-tool/certs/elastic1-key.pem
    generateCertificateconfiguration elastic2 1.1.1.2
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/elastic2-key.pem -out /tmp/wazuh-cert-tool/certs/elastic2.csr -config /tmp/wazuh-cert-tool/certs/elastic2.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/elastic2.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/elastic2.pem -extfile /tmp/wazuh-cert-tool/certs/elastic2.conf -extensions v3_req -days 3650
    chmod 444 /tmp/wazuh-cert-tool/certs/elastic2-key.pem

}

function load-generateFilebeatcertificates() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateFilebeatcertificates
}

test-11-generateFilebeatcertificates-no-nodes() {
    load-generateFilebeatcertificates
    wazuh_servers_node_names=()
    generateFilebeatcertificates
    @assert-success
}

test-12-generateFilebeatcertificates-two-nodes() {
    load-generateFilebeatcertificates
    wazuh_servers_node_names=("wazuh1" "wazuh2")
    wazuh_servers_node_ips=("1.1.1.1" "1.1.1.2")
    generateFilebeatcertificates
}

test-12-generateFilebeatcertificates-two-nodes-assert() {
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/wazuh1-key.pem -out /tmp/wazuh-cert-tool/certs/wazuh1.csr -config /tmp/wazuh-cert-tool/certs/wazuh1.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/wazuh1.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/wazuh1.pem -extfile /tmp/wazuh-cert-tool/certs/wazuh1.conf -extensions v3_req -days 3650
    generateCertificateconfiguration "wazuh2" "1.1.1.2"
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/wazuh2-key.pem -out /tmp/wazuh-cert-tool/certs/wazuh2.csr -config /tmp/wazuh-cert-tool/certs/wazuh2.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/wazuh2.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/wazuh2.pem -extfile /tmp/wazuh-cert-tool/certs/wazuh2.conf -extensions v3_req -days 3650

}

function load-generateKibanacertificates() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateKibanacertificates
}

test-13-generateKibanacertificates-no-nodes() {
    load-generateKibanacertificates
    kibana_node_names=()
    generateKibanacertificates
    @assert-success
}

test-14-generateKibanacertificates-two-nodes() {
    load-generateKibanacertificates
    kibana_node_names=("kibana1" "kibana2")
    kibana_node_ips=("1.1.1.1" "1.1.1.2")
    generateKibanacertificates
}

test-14-generateKibanacertificates-two-nodes-assert() {
    generateCertificateconfiguration "kibana1" "1.1.1.1"
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/kibana1-key.pem -out /tmp/wazuh-cert-tool/certs/kibana1.csr -config /tmp/wazuh-cert-tool/certs/kibana1.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/kibana1.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/kibana1.pem -extfile /tmp/wazuh-cert-tool/certs/kibana1.conf -extensions v3_req -days 3650
    chmod 444 /tmp/wazuh-cert-tool/certs/kibana1-key.pem
    generateCertificateconfiguration "kibana2" "1.1.1.2"
    openssl req -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/kibana2-key.pem -out /tmp/wazuh-cert-tool/certs/kibana2.csr -config /tmp/wazuh-cert-tool/certs/kibana2.conf -days 3650
    openssl x509 -req -in /tmp/wazuh-cert-tool/certs/kibana2.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -out /tmp/wazuh-cert-tool/certs/kibana2.pem -extfile /tmp/wazuh-cert-tool/certs/kibana2.conf -extensions v3_req -days 3650
    chmod 444 /tmp/wazuh-cert-tool/certs/kibana2-key.pem
}

function load-readConfig() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" readConfig
    config_file="${base_path}/config.yml"
}

test-ASSERT-FAIL-15-readConfig-empty-file() {
    load-readConfig
    @mkdir -p ${base_dir}
    @rm "${config_file}"
    @touch ${config_file}
    readConfig
    @rm ${config_file}
}

test-ASSERT-FAIL-16-readConfig-no-file() {
    load-readConfig
    @rm "${config_file}"
    readConfig
}

test-ASSERT-FAIL-17-readConfig-duplicated-elastic-node-names() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2 1.1.1.3"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 1.1.1.3 === @out "1.1.1.1 1.1.1.2 1.1.1.3"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo master
    @mocktrue echo worker
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1

    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-18-readConfig-duplicated-elastic-node-ips() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.1"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.1 === @out "1.1.1.1"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo master
    @mocktrue echo worker
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-19-readConfig-duplicated-wazuh-node-names() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh1 === @out "(wazuh1)"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo wazuh1
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-20-readConfig-duplicated-wazuh-node-ips() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.1 === @out "1.1.2.1"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo master
    @mocktrue echo worker
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-21-readConfig-duplicated-kibana-node-names() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana1"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.1 === @out "(1.1.2.1)"
    @mock echo kibana1 kibana1 === @out "(kibana1)"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo master
    @mocktrue echo worker
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-22-readConfig-duplicated-kibana-node-ips() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.1.3.1"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.1 === @out "1.1.2.1"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.1 === @out "1.1.3.1"
    @mocktrue echo master
    @mocktrue echo worker
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-23-readConfig-different-number-of-wazuh-names-and-ips() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 === @out "(wazuh1)"
    @mock echo 1.1.2.1 1.1.2.1 === @out "1.1.2.1"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo wazuh1
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-24-readConfig-incorrect-wazuh-node-type() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "worker master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.1 === @out "1.1.2.1"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mock echo wazuh1
    @mock echo wazuh2
    @mockfalse grep -ioq master
    @mockfalse grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-25-readConfig-wazuh-node-type-one-node() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 === @out "wazuh1"
    @mock echo 1.1.2.1 1.1.2.1 === @out "1.1.2.1"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mock echo wazuh1
    @mockfalse grep -ioq master
    @mockfalse grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-26-readConfig-less-wazuh-node-types-than-nodes() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "master"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mock echo wazuh1
    @mock echo wazuh2
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1
    
    readConfig
    @rm "${config_file}"
}

test-ASSERT-FAIL-27-readConfig-different-number-of-kibana-names-and-ips() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.1.3.2 1.1.3.3"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "master worker"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 1.1.3.3=== @out "1.1.3.1 1.1.3.2 1.1.3.)"

    @mock echo wazuh1
    @mock echo wazuh2
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1

    readConfig
    @rm "${config_file}"
}

test-28-readConfig-everything-correct() {
    load-readConfig
    @mkdir -p "${base_path}"
    @touch "${config_file}"
    @echo "config_file" > "${config_file}"
    
    @mock parse_yaml /tmp/wazuh-cert-tool/config.yml === @out
    @mock grep nodes_elasticsearch_name === @out "elastic1 elastic2"
    @mock sed 's/nodes_elasticsearch_name=//'
    @mock grep nodes_wazuh_servers_name === @out "wazuh1 wazuh2"
    @mock sed 's/nodes_wazuh_servers_name=//'
    @mock grep nodes_kibana_name === @out "kibana1 kibana2"
    @mock sed 's/nodes_kibana_name=//'

    @mock grep nodes_elasticsearch_ip === @out "1.1.1.1 1.1.1.2"
    @mock sed 's/nodes_elasticsearch_ip=//'
    @mock grep nodes_wazuh_servers_ip === @out "1.1.2.1 1.1.2.2"
    @mock sed 's/nodes_wazuh_servers_ip=//'
    @mock grep nodes_kibana_ip === @out "1.1.3.1 1.1.3.2"
    @mock sed 's/nodes_kibana_ip=//'

    @mock grep nodes_wazuh_servers_node_type === @out "master worker"
    @mock sed 's/nodes_wazuh_servers_node_type=//'

    @mock tr ' ' '\n'
    @mock sort -u
    @mock tr '\n' ' '
    @mock echo elastic1 elastic2 === @out "elastic1 elastic2"
    @mock echo 1.1.1.1 1.1.1.2 === @out "1.1.1.1 1.1.1.2"
    @mock echo wazuh1 wazuh2 === @out "wazuh1 wazuh2"
    @mock echo 1.1.2.1 1.1.2.2 === @out "1.1.2.1 1.1.2.2"
    @mock echo kibana1 kibana2 === @out "kibana1 kibana2"
    @mock echo 1.1.3.1 1.1.3.2 === @out "1.1.3.1 1.1.3.2"

    @mocktrue echo "master"
    @mocktrue echo "worker"
    @mocktrue grep -ioq master
    @mocktrue grep -ioq worker

    @mock wc -l
    @mock grep -io master === @out 1
    @mock grep -io worker === @out 1

    readConfig
    @rm "${config_file}"
    @echo "${elasticsearch_node_names[@]}"
    @echo "${elasticsearch_node_ips[@]}"
    @echo "${wazuh_servers_node_names[@]}"
    @echo "${wazuh_servers_node_ips[@]}"
    @echo "${kibana_node_names[@]}"
    @echo "${kibana_node_ips[@]}"
}

test-28-readConfig-everything-correct-assert() {
    @echo elastic1 elastic2
    @echo 1.1.1.1 1.1.1.2
    @echo wazuh1 wazuh2
    @echo 1.1.2.1 1.1.2.2
    @echo kibana1 kibana2
    @echo 1.1.3.1 1.1.3.2
}
