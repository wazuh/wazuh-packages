#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../../"$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/test/bach.sh

@setup-test {
    @ignore logger
}

function load-get-config() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" getConfig
}

test-get-config-no-args() {
    load-get-config
    getConfig
}

test-get-config-no-args-assert() {
    exit 1
}

test-get-config-one-argument() {
    load-get-config
    getConfig "elasticsearch"
}

test-get-config-one-argument-assert() {
    exit 1
}

test-get-config-local() {
    load-get-config
    base_path="/tmp"
    config_path="example"
    local=1
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-local-assert() {
    cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-get-config-online() {
    load-get-config
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
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
#     # @mockfalse -n "$(command -v yum)"
#     # @mockfalse -n "$(command -v zypper)"
#     # @mockfalse -n "$(command -v apt-get)"
#     checkSystem
#     @assert-fail
# }

# test-check-system-yum() {
#     load-check-system
#     # @mocktrue -n "$(command -v yum)"
#     # @mockfalse -n "$(command -v zypper)"
#     # @mockfalse -n "$(command -v apt-get)"
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
#     # @mockfalse -n "$(command -v yum)"
#     # @mocktrue -n "$(command -v zypper)"
#     # @mockfalse -n "$(command -v apt)"
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
#     # @mockfalse -n "$(command -v yum)"
#     # @mockfalse -n "$(command -v zypper)"
#     # @mocktrue -n "$(command -v apt-get)"
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
    exit 1
}

test-check-names-elastic-wazuh-equals() {
    load-check-names
    einame="node1"
    winame="node1"
    checkNames
}

test-check-names-elastic-wazuh-equals-assert() {
    exit 1
}

test-check-names-kibana-wazuh-equals() {
    load-check-names
    kiname="node1"
    winame="node1"
    checkNames
}

test-check-names-kibana-wazuh-equals-assert() {
    exit 1
}

test-check-names-wazuh-node-name-not-in-config() {
    load-check-names
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checkNames
}

test-check-names-wazuh-node-name-not-in-config-assert() {
    exit 1
}

test-check-names-kibana-node-name-not-in-config() {
    load-check-names
    kiname="node1"
    kibana_node_names=(kibana node10)
    @mock echo ${kibana_node_names[@]} === @out kibana node10
    @mock grep -w $kiname === @false
    checkNames
}

test-check-names-kibana-node-name-not-in-config-assert() {
    exit 1
}

test-check-names-elasticsearch-node-name-not-in-config() {
    load-check-names
    einame="node1"
    elasticsearch_node_names=(elasticsearch node10)
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch node10
    @mock grep -w $einame === @false
    checkNames
}

test-check-names-elasticsearch-node-name-not-in-config-assert() {
    exit 1
}

test-check-names-all-correct() {
    load-check-names
    einame="elasticsearch1"
    kiname="kibana1"
    wazuh="wazuh1"
    elasticsearch_node_names=(elasticsearch1 node1)
    wazuh_servers_node_names=(wazuh1 node2)
    kibana_node_names=(kibana1 node3)
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch1 node1
    @mock grep -w $einame === @out elasticsearch1
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh1 node2
    @mock grep -w $winame === @out wazuh1
    @mock echo ${kibana_node_names[@]} === @out kibana1 node3
    @mock grep -w $kiname === @out kibana1
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
    exit 1
}

test-check-arch-i386() {
    @mock uname -m === @out i386
    load-check-arch
    checkArch
}

test-check-arch-i386-assert() {
    exit 1
}

function load-install-prerequisites() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" installPrerequisites
}

test-install-prerequisites-yum-no-openssl() {
    #@mock command -v openssl === @out 
    load-install-prerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-install-prerequisites-yum-no-openssl-assert() {
    yum install curl unzip wget libcap tar gnupg openssl -y
}

# test-install-prerequisites-yum() {
#     #@mock command -v openssl === @out /usr/bin/openssl
#     load-install-prerequisites
#     sys_type="yum"
#     debug=""
#     installPrerequisites
# }

# test-install-prerequisites-yum-assert() {
#     yum install curl unzip wget libcap tar gnupg -y
# }

test-install-prerequisites-zypper-no-openssl() {
    #@mock command -v openssl === @out
    @mocktrue zypper -n install libcap-progs tar gnupg
    load-install-prerequisites
    sys_type="zypper"
    debug=""
    installPrerequisites
}

test-install-prerequisites-zypper-no-openssl-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap-progs tar gnupg openssl
}

# test-install-prerequisites-zypper-no-libcap-progs() {
#     #@mock command -v openssl === @out /usr/bin/openssl
#     @mockfalse zypper -n install libcap-progs tar gnupg
#     load-install-prerequisites
#     sys_type="zypper"
#     debug=""
#     installPrerequisites
# }

# test-install-prerequisites-zypper-no-libcap-progs-assert() {
#     zypper -n install curl unzip wget
#     zypper -n install libcap2 tar gnupg
# }

test-install-prerequisites-apt-no-openssl() {
    #@mock command -v openssl === @out 
    load-install-prerequisites
    sys_type="apt-get"
    debug=""
    installPrerequisites
}

test-install-prerequisites-apt-no-openssl-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg openssl -y
}

# test-install-prerequisites-apt() {
#     #@mock command -v openssl === @out /usr/bin/openssl
#     load-install-prerequisites
#     sys_type="apt-get"
#     debug=""
#     installPrerequisites
# }

# test-install-prerequisites-apt-assert() {
#     apt-get update -q
#     apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg -y
# }

function load-add-repo() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" addWazuhrepo
}

test-add-wazuh-repo-yum() {
    load-add-repo
    development=1
    sys_type="yum"
    debug=""
    repogpg=""
    releasever=""
    @rm /etc/yum.repos.d/wazuh.repo
    @rm /etc/zypp/repos.d/wazuh.repo
    @rm /etc/apt/sources.list.d/wazuh.list
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1' 
    @mocktrue tee /etc/yum.repos.d/wazuh.repo
    addWazuhrepo
}

test-add-wazuh-repo-yum-assert() {
    rm -f /etc/yum.repos.d/wazuh.repo
    rpm --import
}

test-add-wazuh-repo-zypper() {
    load-add-repo
    development=1
    sys_type="zypper"
    debug=""
    repogpg=""
    releasever=""
    @rm /etc/yum.repos.d/wazuh.repo
    @rm /etc/zypp/repos.d/wazuh.repo
    @rm /etc/apt/sources.list.d/wazuh.list
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1'
    @mocktrue tee /etc/zypp/repos.d/wazuh.repo
    addWazuhrepo
}

test-add-wazuh-repo-zypper-assert() {
    rm -f /etc/zypp/repos.d/wazuh.repo
    rpm --import
}

test-add-wazuh-repo-apt() {
    load-add-repo
    development=1
    sys_type="apt-get"
    debug=""
    repogpg=""
    releasever=""
    @rm /etc/yum.repos.d/wazuh.repo
    @rm /etc/zypp/repos.d/wazuh.repo
    @rm /etc/apt/sources.list.d/wazuh.list
    @mocktrue curl -s --max-time 300
    @mocktrue apt-key add -
    @mocktrue echo "deb /apt/  main"
    @mocktrue tee /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-apt-assert() {
    rm -f /etc/apt/sources.list.d/wazuh.list
    apt-get update -q
}

test-add-wazuh-repo-yum-file-present() {
    load-add-repo
    development=""
    @touch /etc/yum.repos.d/wazuh.repo
    @rm /etc/zypp/repos.d/wazuh.repo
    @rm /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-zypper-file-present() {
    load-add-repo
    development=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mockfalse ! -f /etc/zypp/repos.d/wazuh.repo
    @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

test-add-wazuh-repo-apt-file-present() {
    load-add-repo
    development=""
    @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
    @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
    @mockfalse ! -f /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
}

function load-restore-repo() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" restoreWazuhrepo
}

test-restore-wazuh-repo-no-dev() {
    load-restore-repo
    development=""
    restoreWazuhrepo
    @assert-success
}

test-restore-wazuh-repo-yum() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mocktrue -f /etc/yum.repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-yum-assert() {
    file="/etc/yum.repos.d/wazuh.repo"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
}

test-restore-wazuh-repo-apt() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mocktrue -f /etc/apt/sources.list.d/wazuh.list
    restoreWazuhrepo
}

test-restore-wazuh-repo-apt-assert() {
    file="/etc/apt/sources.list.d/wazuh.list"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
}

test-restore-wazuh-repo-zypper() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mocktrue -f /etc/zypp/repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-zypper-assert() {
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g' ${file}
    sed -i 's/pre-release/4.x/g' ${file}
    sed -i 's/unstable/stable/g' ${file}
}

test-restore-wazuh-repo-yum-no-file() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mockfalse -f /etc/yum.repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-yum-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-restore-wazuh-repo-apt-no-file() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mockfalse -f /etc/apt/sources.list.d/wazuh.list
    restoreWazuhrepo
}

test-restore-wazuh-repo-apt-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-restore-wazuh-repo-zypper() {
    load-restore-repo
    development="1"
    sys_type="yum"
    #@mockfalse -f /etc/zypp/repos.d/wazuh.repo
    restoreWazuhrepo
}

test-restore-wazuh-repo-zypper-assert() {
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

function load-check-arguments {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkArguments
}

test-check-arguments-certs-file-present-aio() {
    load-check-arguments
    AIO=1
    #@mocktrue -d ${base_path}/certs
    checkArguments
}

test-check-arguments-certs-file-present-aio-assert() {
    exit 1
}

test-check-arguments-certs-file-present-certificate-creation() {
    load-check-arguments
    certificates=1
    #@mocktrue -d ${base_path}/certs
    checkArguments
}

test-check-arguments-certs-file-present-certificate-creation-assert() {
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
    exit 1
}

test-check-arguments-uninstall-no-apps-installed() {
    load-check-arguments
    uninstall=1
    elasticsearchinstalled=""
    elastic_remaining_files=""
    wazuhinstalled=""
    wazuh_remaining_files=""
    kibanainstalled=""
    kibana_remaining_files=""
    filebeatinstalled=""
    filebeat_remaining_files=""
    checkArguments
}

test-check-arguments-uninstall-and-aio() {
    load-check-arguments
    uninstall=1
    AIO=1
    checkArguments
}

test-check-arguments-uninstall-and-aio-assert() {
    exit 1
}

test-check-arguments-uninstall-and-wazuh() {
    load-check-arguments
    uninstall=1
    wazuh=1
    checkArguments
}

test-check-arguments-uninstall-and-wazuh-assert() {
    exit 1
}

test-check-arguments-uninstall-and-kibana() {
    load-check-arguments
    uninstall=1
    kibana=1
    checkArguments
}

test-check-arguments-uninstall-and-kibana-assert() {
    exit 1
}

test-check-arguments-uninstall-and-elasticsearch() {
    load-check-arguments
    uninstall=1
    elasticsearch=1
    checkArguments
}

test-check-arguments-uninstall-and-elasticsearch-assert() {
    exit 1
}

test-check-arguments-install-aio-and-elastic () {
    load-check-arguments
    AIO=1
    elasticsearch=1
    checkArguments
}

test-check-arguments-install-aio-and-elastic-assert() {
    exit 1
}

test-check-arguments-install-aio-and-wazuh () {
    load-check-arguments
    AIO=1
    wazuh=1
    checkArguments
}

test-check-arguments-install-aio-and-wazuh-assert() {
    exit 1
}

test-check-arguments-install-aio-and-kibana () {
    load-check-arguments
    AIO=1
    kibana=1
    checkArguments
}

test-check-arguments-install-aio-and-kibana-assert() {
    exit 1
}

test-check-arguments-install-aio-wazuh-installed-no-overwrite() {
    load-check-arguments
    AIO=1
    wazuhinstalled=1
    checkArguments
}

test-check-arguments-install-aio-wazuh-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-wazuh-files-no-overwrite() {
    load-check-arguments
    AIO=1
    wazuh_remaining_files=1
    checkArguments
}

test-check-arguments-install-aio-wazuh-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-elastic-installed-no-overwrite() {
    load-check-arguments
    AIO=1
    elasticsearchinstalled=1
    checkArguments
}

test-check-arguments-install-aio-elastic-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-elastic-files-no-overwrite() {
    load-check-arguments
    AIO=1
    elastic_remaining_files=1
    checkArguments
}

test-check-arguments-install-aio-elastic-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-kibana-installed-no-overwrite() {
    load-check-arguments
    AIO=1
    kibanainstalled=1
    checkArguments
}

test-check-arguments-install-aio-kibana-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-kibana-files-no-overwrite() {
    load-check-arguments
    AIO=1
    kibana_remaining_files=1
    checkArguments
}

test-check-arguments-install-aio-kibana-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-aio-wazuh-installed() {
    load-check-arguments
    AIO=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-wazuh-installed-assert() {
    rollBack
}

test-check-arguments-install-aio-wazuh-files() {
    load-check-arguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-wazuh-files-assert() {
    rollBack
}

test-check-arguments-install-aio-elastic-installed() {
    load-check-arguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-elastic-installed-assert() {
    rollBack
}

test-check-arguments-install-aio-elastic-files() {
    load-check-arguments
    AIO=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-elastic-files-assert() {
    rollBack
}

test-check-arguments-install-aio-kibana-installed() {
    load-check-arguments
    AIO=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-kibana-installed-assert() {
    rollBack
}

test-check-arguments-install-aio-kibana-files() {
    load-check-arguments
    AIO=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-aio-kibana-files-assert() {
    rollBack
}

test-check-arguments-install-elastic-already-installed-no-overwrite() {
    load-check-arguments
    elasticsearch=1
    elasticsearchinstalled=1
    checkArguments
}

test-check-arguments-install-elastic-already-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-elastic-remaining-files-no-overwrite() {
    load-check-arguments
    elasticsearch=1
    elastic_remaining_files=1
    checkArguments
}

test-check-arguments-install-elastic-remaining-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-elastic-already-installed() {
    load-check-arguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-elastic-already-installed-assert() {
    rollBack
}

test-check-arguments-install-elastic-remaining-files() {
    load-check-arguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-elastic-remaining-files-assert() {
    rollBack
}

test-check-arguments-install-wazuh-already-installed-no-overwrite() {
    load-check-arguments
    wazuh=1
    wazuhinstalled=1
    checkArguments
}

test-check-arguments-install-wazuh-already-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-wazuh-remaining-files-no-overwrite() {
    load-check-arguments
    wazuh=1
    wazuh_remaining_files=1
    checkArguments
}

test-check-arguments-install-wazuh-remaining-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-wazuh-already-installed() {
    load-check-arguments
    wazuh=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-wazuh-already-installed-assert() {
    rollBack
}

test-check-arguments-install-wazuh-remaining-files() {
    load-check-arguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-wazuh-remaining-files-assert() {
    rollBack
}

test-check-arguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-check-arguments
    wazuh=1
    filebeatinstalled=1
    checkArguments
}

test-check-arguments-install-wazuh-filebeat-already-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-check-arguments
    wazuh=1
    filebeat_remaining_files=1
    checkArguments
}

test-check-arguments-install-wazuh-filebeat-remaining-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-wazuh-already-installed() {
    load-check-arguments
    wazuh=1
    filebeatinstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-wazuh-filebeat-already-installed-assert() {
    rollBack
}

test-check-arguments-install-wazuh-filebeat-remaining-files() {
    load-check-arguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-wazuh-remaining-files-assert() {
    rollBack
}

test-check-arguments-install-kibana-already-installed-no-overwrite() {
    load-check-arguments
    kibana=1
    kibanainstalled=1
    checkArguments
}

test-check-arguments-install-kibana-already-installed-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-kibana-remaining-files-no-overwrite() {
    load-check-arguments
    kibana=1
    kibana_remaining_files=1
    checkArguments
}

test-check-arguments-install-kibana-remaining-files-no-overwrite-assert() {
    exit 1
}

test-check-arguments-install-kibana-already-installed() {
    load-check-arguments
    kibana=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-kibana-already-installed-assert() {
    rollBack
}

test-check-arguments-install-kibana-remaining-files() {
    load-check-arguments
    kibana=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-check-arguments-install-kibana-remaining-files-assert() {
    rollBack
}

function load-create-cluster-key {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" createClusterKey
}

test-create-cluster-key() {
    load-create-cluster-key
    base_path=/tmp
}

test-create-cluster-key-assert() {
    openssl rand -hex 16 >> ${base_path}/certs/clusterkey
}