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

test-cleanFiles-1() {
    load-cleanFiles
    cleanFiles
}

test-cleanFiles-1-assert() {
    rm -f /tmp/wazuh-cert-tool/certs/*.csr
    rm -f /tmp/wazuh-cert-tool/certs/*.srl
    rm -f /tmp/wazuh-cert-tool/certs/*.conf
    rm -f /tmp/wazuh-cert-tool/certs/admin-key-temp.pem
}

function load-checkOpenSSL() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" checkOpenSSL
}

test-ASSERT-FAIL-checkOpenSSL-no-openssl-2() {
    load-checkOpenSSL
    @mock command -v openssl === @out ""
    checkOpenSSL
}

test-checkOpenSSL-correct-3() {
    load-checkOpenSSL
    @mock command -v openssl === @out "/bin/openssl"
    checkOpenSSL
    @assert-success
}

function load-generateAdmincertificate() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateAdmincertificate
}

test-generateAdmincertificate-4() {
    load-generateAdmincertificate
    generateAdmincertificate
}

test-generateAdmincertificate-4-assert() {
    openssl genrsa -out /tmp/wazuh-cert-tool/certs/admin-key-temp.pem 2048
    openssl pkcs8 -inform PEM -outform PEM -in /tmp/wazuh-cert-tool/certs/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out /tmp/wazuh-cert-tool/certs/admin-key.pem
    openssl req -new -key /tmp/wazuh-cert-tool/certs/admin-key.pem -out /tmp/wazuh-cert-tool/certs/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Docu/CN=admin'
    openssl x509 -days 3650 -req -in /tmp/wazuh-cert-tool/certs/admin.csr -CA /tmp/wazuh-cert-tool/certs/root-ca.pem -CAkey /tmp/wazuh-cert-tool/certs/root-ca.key -CAcreateserial -sha256 -out /tmp/wazuh-cert-tool/certs/admin.pem
}

function load-generateCertificateconfiguration() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateCertificateconfiguration
}

test-generateCertificateconfiguration-IP-5() {
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

test-generateCertificateconfiguration-IP-5-assert() {
    echo "conf"
    echo "conf2"
}

test-generateCertificateconfiguration-DNS-6() {
    load-generateCertificateconfiguration
    @mkdir -p /tmp/wazuh-cert-tool/certs
    @touch /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @mock echo 1.1.1.1 === @out ""
    @mock awk "{sub(\"CN = cname\", \"CN = wazuh1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf"
    @mock awk "{sub(\"CN = cname\", \"CN = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf2"
    @mock awk "{sub(\"IP.1 = cip\", \"DNS.1 = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf3"
    @mock grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" === @out ""
    @mock grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" === @out "1.1.1.1"
    @mocktrue cat
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    @rm /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @rmdir /tmp/wazuh-cert-tool/certs
}

test-generateCertificateconfiguration-DNS-6-assert() {
    echo "conf"
    echo "conf2"
    echo "conf3"
}

test-ASSERT-FAIL-generateCertificateconfiguration-error-7() {
    load-generateCertificateconfiguration
    @mkdir -p /tmp/wazuh-cert-tool/certs
    @touch /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @mock echo 1.1.1.1 === @out ""
    @mock awk "{sub(\"CN = cname\", \"CN = wazuh1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf"
    @mock awk "{sub(\"CN = cname\", \"CN = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf2"
    @mock awk "{sub(\"IP.1 = cip\", \"DNS.1 = 1.1.1.1\")}1" "/tmp/wazuh-cert-tool/certs/wazuh1.conf" === @out "conf3"
    @mock grep -P "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" === @out ""
    @mock grep -P "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$" === @out ""
    @mocktrue cat
    generateCertificateconfiguration "wazuh1" "1.1.1.1"
    @rm /tmp/wazuh-cert-tool/certs/wazuh1.conf
    @rmdir /tmp/wazuh-cert-tool/certs
}


function load-generateRootCAcertificate() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateRootCAcertificate
}

test-generateRootCAcertificate-8() {
    load-generateRootCAcertificate
    generateRootCAcertificate
}

test-generateRootCAcertificate-8-assert() {
    openssl req -x509 -new -nodes -newkey rsa:2048 -keyout /tmp/wazuh-cert-tool/certs/root-ca.key -out ${base_path}/certs/root-ca.pem -batch -subj '/OU=Docu/O=Wazuh/L=California/' -days 3650
}

function load-generateElasticsearchcertificates() {
    @load_function "${base_dir}/wazuh-cert-tool.sh" generateElasticsearchcertificates
}

test-generateElasticsearchcertificates-no-nodes-9() {
    
}