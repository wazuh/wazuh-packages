#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../../"$(dirname "$BASH_SOURCE")"; pwd -P)"
source "${base_dir}"/test/bach.sh


function load-get-config() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" getConfig
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
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkSystem
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
#     @mocktrue -n "$(command -v yum)"
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
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkNames
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
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkArch
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
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" installPrerequisites
}

# test-install-prerequisites-yum-no-openssl() {
#     @mock command -v openssl === @out 
#     load-install-prerequisites
#     sys_type="yum"
#     debug=""
#     installPrerequisites
# }

test-install-prerequisites-yum-no-openssl-assert() {
    logger "Starting all necessary utility installation."
    yum install curl unzip wget libcap tar gnupg -y
    logger "All necessary utility installation finished."
}

# test-install-prerequisites-yum() {
#     @mock command -v openssl === @out /usr/bin/openssl
#     @mocktrue yum install curl unzip wget libcap tar gnupg -y
#     load-install-prerequisites
#     sys_type="yum"
#     debug=""
#     installPrerequisites
#}

test-install-prerequisites-yum-assert() {
    logger "Starting all necessary utility installation."
    yum install curl unzip wget libcap tar gnupg openssl -y
    logger "All necessary utility installation finished."
}

function load-add-repo() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" addWazuhrepo
}

test-add-wazuh-repo-yum() {
    load-add-repo
    local development=1
    local sys_type="yum"
    local debug=""
    local repogpg=""
    local releasever=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
    @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1' 
    @mocktrue tee /etc/yum.repos.d/wazuh.repo
    addWazuhrepo
}

test-add-wazuh-repo-yum-assert() {
    logger "Adding the Wazuh repository."
    rm -f /etc/yum.repos.d/wazuh.repo
    rpm --import
    logger "Wazuh repository added."
}

test-add-wazuh-repo-zypper() {
    load-add-repo
    local development=1
    local sys_type="zypper"
    local debug=""
    local repogpg=""
    local releasever=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
    @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1'
    @mocktrue tee /etc/zypp/repos.d/wazuh.repo
    addWazuhrepo
}

test-add-wazuh-repo-zypper-assert() {
    logger "Adding the Wazuh repository."
    rm -f /etc/zypp/repos.d/wazuh.repo
    rpm --import
    logger "Wazuh repository added."
}

test-add-wazuh-repo-apt() {
    load-add-repo
    local development=1
    local sys_type="apt-get"
    local debug=""
    local repogpg=""
    local releasever=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
    @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
    @mocktrue curl -s --max-time 300
    @mocktrue apt-key add -
    @mocktrue echo "deb /apt/  main"
    @mocktrue tee /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-apt-assert() {
    logger "Adding the Wazuh repository."
    rm -f /etc/apt/sources.list.d/wazuh.list
    apt-get update -q
    logger "Wazuh repository added."
}

test-add-wazuh-repo-yum-file-present() {
    load-add-repo
    local development=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mockfalse ! -f /etc/zypp/repos.d/wazuh.repo
    @mockfalse ! -f /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-yum-file-present-assert() {
    logger "Adding the Wazuh repository."
    logger "Wazuh repository already exists skipping."
    logger "Wazuh repository added."
}

test-add-wazuh-repo-zypper-file-present() {
    load-add-repo
    local development=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mockfalse ! -f /etc/zypp/repos.d/wazuh.repo
    @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-zypper-file-present-assert() {
    logger "Adding the Wazuh repository."
    logger "Wazuh repository already exists skipping."
    logger "Wazuh repository added."
}

test-add-wazuh-repo-apt-file-present() {
    load-add-repo
    local development=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
    @mockfalse ! -f /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-apt-file-present-assert() {
    logger "Adding the Wazuh repository."
    logger "Wazuh repository already exists skipping."
    logger "Wazuh repository added."
}

function load-restore-repo() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" restoreWazuhrepo
}

test-restore-wazuh-repo-no-dev() {
    load-restore-repo
    local development=""
    restoreWazuhrepo
    @assert-success
}

test-restore-wazuh-repo-yum() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mocktrue -f /etc/yum.repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-yum-assert() {
    logger "Setting the Wazuh repository to production."
    file="/etc/yum.repos.d/wazuh.repo"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
    logger "The Wazuh repository set to production."
}

test-restore-wazuh-repo-apt() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mocktrue -f /etc/apt/sources.list.d/wazuh.list
    restoreWazuhrepo
}

test-restore-wazuh-repo-apt-assert() {
    logger "Setting the Wazuh repository to production."
    file="/etc/apt/sources.list.d/wazuh.list"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
    logger "The Wazuh repository set to production."
}

test-restore-wazuh-repo-zypper() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mocktrue -f /etc/zypp/repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-zypper-assert() {
    logger "Setting the Wazuh repository to production."
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
    logger "The Wazuh repository set to production."
}

test-restore-wazuh-repo-yum-no-file() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mockfalse -f /etc/yum.repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-yum-assert() {
    logger "Setting the Wazuh repository to production."
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
    logger "The Wazuh repository set to production."
}

test-restore-wazuh-repo-apt-no-file() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mockfalse -f /etc/apt/sources.list.d/wazuh.list
    restoreWazuhrepo
}

test-restore-wazuh-repo-apt-assert() {
    logger "Setting the Wazuh repository to production."
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
    logger "The Wazuh repository set to production."
}

test-restore-wazuh-repo-zypper() {
    load-restore-repo
    local development="1"
    local sys_type="yum"
    #@mockfalse -f /etc/zypp/repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-zypper-assert() {
    logger "Setting the Wazuh repository to production."
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
    logger "The Wazuh repository set to production."
}

function load-check-arguments {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkArguments
}

test-check-arguments-certs-file-present-aio() {
    load-check-arguments
    local AIO=1
    #@mocktrue -d ${base_path}/certs
    checkArguments
}

test-check-arguments-certs-file-present-aio-assert() {
    logger -e "Folder /certs already exists. Please, remove the certificates folder to create new certificates."
    exit 1
}

test-check-arguments-certs-file-present-certificate-creation() {
    load-check-arguments
    local certificates=1
    #@mocktrue -d ${base_path}/certs
    checkArguments
}

test-check-arguments-certs-file-present-certificate-creation-assert() {
    logger -e "Folder /certs already exists. Please, remove the certificates folder to create new certificates."
    exit 1
}

test-check-arguments-overwrite-with-no-installation() {
    load-check-arguments
    overwrite=1
    AIO=
    elasticsearch=
    wazuh=
    kibana=
    checkArguments
}

test-check-test-check-arguments-overwrite-with-no-installation-assert() {
    logger -e "Missing arguments. The option -o|--overwrite can not be used alone. Expected -a, -e, -k, or -w options. To uninstall components, use -u|--uninstall instead."
    exit 1
}

test-check-arguments-uninstall-no-apps-installed() {
    uninstall=1
    elasticsearchinstalled=
    wazuhinstalled=
    kibanainstalled=
    filebeatinstalled=
}