#!/usr/bin/env bash
set -euo pipefail
curr_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P)"
source "${curr_dir}"/bach.sh


function load-get-config() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" getConfig
}

test-get-config-empty() {
    load-get-config
    getConfig
}

test-get-config-empty-assert() {
    logger -e "getConfig must be called with 2 arguments."
    exit 1
}

test-get-config-one-argument() {
    load-get-config
    getConfig "elasticsearch"
}

test-get-config-one-argument-assert() {
    logger -e "getConfig must be called with 2 arguments."
    exit 1
}

test-get-config-local() {
    load-get-config
    local base_path=/tmp
    local config_path=example
    local local=1
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-local-assert() {
    cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-online() {
    load-get-config
    local base_path="/tmp"
    local config_path="example"
    resources_config="example.com/config"
    local local=
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-online-assert() {
    curl -so /tmp/elasticsearch/elasticsearch.yml example.com/config/elasticsearch.yml
}

function load-check-system() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" checkSystem
}

# test-check-system-no-system() {
#     load-check-system
#     @mockfalse -n "$(command -v yum)"
#     @mockfalse -n "$(command -v zypper)"
#     @mockfalse -n "$(command -v apt-get)"
#     checkSystem
# }

# test-check-system-no-system-assert() {
#     logger -e "Couldn't find type of system based on the installer software"
#     exit 1
# }

# test-check-system-yum() {
#     load-check-system
#     @mocktrue - "$(command -v yum)"
#     @mockfalse -n "$(command -v zypper)"
#     @mockfalse -n "$(command -v apt-get)"
#     checkSystem
#     echo "$sys_type"
#     echo "$sep"
# }

# test-check-system-yum-assert() {
#     sys_type="yum"
#     sep="-"
#     echo "$sys_type"
#     echo "$sep"
# }

# test-check-system-zypper() {
#     load-check-system
#     @mockfalse -n "$(command -v yum)"
#     @mocktrue -n "$(command -v zypper)"
#     @mockfalse -n "$(command -v apt)"
#     checkSystem
#     echo "$sys_type"
#     echo "$sep"
# }

# test-check-system-zypper-assert() {
#     sys_type="zypper"
#     sep="-"
#     echo "$sys_type"
#     echo "$sep"
# }

# test-check-system-apt() {
#     load-check-system
#     @mockfalse -n "$(command -v yum)"
#     @mockfalse -n "$(command -v zypper)"
#     @mocktrue -n "$(command -v apt-get)"
#     checkSystem
#     echo "$sys_type"
#     echo "$sep"
# }

# test-check-system-apt-assert() {
#     sys_type="apt-get"
#     sep="="
#     echo "$sys_type"
#     echo "$sep"
# }

function load-check-names() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" checkNames
}

test-check-names-elastic-kibana-equals() {
    load-check-names
    einame="node1"
    kiname="node1"
    checkNames
}

test-check-names-elastic-kibana-equals-assert() {
    logger -e "The node names for Elastisearch and Kibana must be different."
    exit 1
}

test-check-names-elastic-wazuh-equals() {
    load-check-names
    einame="node1"
    winame="node1"
    checkNames
}

test-check-names-elastic-wazuh-equals-assert() {
    logger -e "The node names for Elastisearch and Wazuh must be different."
    exit 1
}

test-check-names-kibana-wazuh-equals() {
    load-check-names
    kiname="node1"
    winame="node1"
    checkNames
}

test-check-names-kibana-wazuh-equals-assert() {
    logger -e "The node names for Wazuh and Kibana must be different."
    exit 1
}

test-check-names-wazuh-node-name-not-in-config() {
    load-check-names
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    checkNames
}

test-check-names-wazuh-node-name-not-in-config-assert() {
    echo wazuh node10
    grep -w node1
    logger -e "The name given for the Wazuh server node does not appear on the configuration file."
    exit 1
}

test-check-names-kibana-node-name-not-in-config() {
    load-check-names
    kiname="node1"
    kibana_node_names=(kibana node10)
    checkNames
}

test-check-names-kibana-node-name-not-in-config-assert() {
    echo kibana node10
    grep -w node1
    logger -e "The name given for the Kibana node does not appear on the configuration file."
    exit 1
}

test-check-names-elasticsearch-node-name-not-in-config() {
    load-check-names
    einame="node1"
    elasticsearch_node_names=(elasticsearch node10)
    checkNames
}

test-check-names-elasticsearch-node-name-not-in-config-assert() {
    echo elasticsearch node10
    grep -w node1
    logger -e "The name given for the Elasticsearch node does not appear on the configuration file."
    exit 1
}

test-check-names-all-correct() {
    load-check-names
    einame="elasticsearch1"
    kiname="kibana1"
    wazuh="wazuh1"
    elasticsearch_node_names=(elasticsearch1)
    wazuh_servers_node_names=(kibana1)
    kibana_node_names=(wazuh1)
    checkNames
    @assert-success
}

function load-check-arch() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" checkArch
}

test-check-arch-x86_64() {
    @mock uname -m === @out x86_64
    load-check-arch
    checkArch
    @assert-success
}

test-check-arch-empty() {
    @mock uname -m === @out
    load-check-arch
    checkArch
}

test-check-arch-empty-assert() {
    logger -e "Uncompatible system. This script must be run on a 64-bit system."
    exit 1
}

test-check-arch-i386() {
    @mock uname -m === @out i386
    load-check-arch
    checkArch
}

test-check-arch-i386-assert() {
    logger -e "Uncompatible system. This script must be run on a 64-bit system."
    exit 1
}

function load-install-prerequisites() {
    @load_function "${curr_dir}/../install_functions/opendistro/common.sh" installPrerequisites
}

test-install-prerequisites-yum-no-openssl() {
    @mock command -v openssl === @out 
    load-install-prerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-install-prerequisites-yum-no-openssl-assert() {
    logger "Starting all necessary utility installation."
    yum install curl unzip wget libcap tar gnupg -y
    logger "All necessary utility installation finished."
}

test-install-prerequisites-yum() {
    @mock command -v openssl === @out /usr/bin/openssl
    @mocktrue yum install curl unzip wget libcap tar gnupg -y
    load-install-prerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-install-prerequisites-yum-assert() {
    logger "Starting all necessary utility installation."
    yum install curl unzip wget libcap tar gnupg openssl -y
    logger "All necessary utility installation finished."
}