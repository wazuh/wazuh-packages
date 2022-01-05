#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../../"$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/tests/bach.sh

@setup-test {
    @ignore logger
}

function load-getConfig() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" getConfig
}

test-ASSERT-FAIL-getConfig-no-args() {
    load-getConfig
    getConfig
}

test-ASSERT-FAIL-getConfig-one-argument() {
    load-getConfig
    getConfig "elasticsearch"
}

test-getConfig-local() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    local=1
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-getConfig-local-assert() {
    cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-getConfig-online() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-getConfig-online-assert() {
    curl -so /tmp/elasticsearch/elasticsearch.yml example.com/config/elasticsearch.yml
}

function load-checkSystem() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkSystem
}

test-ASSERT-FAIL-checkSystem-empty() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
}

test-checkSystem-yum() {
    load-checkSystem
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v zypper === @false
    @mock command -v apt-get === @false
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-zypper() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @echo /usr/bin/zypper
    @mock command -v apt-get === @false
    checkSystem
    @echo "$sys_type"
    @echo "$sep"
}

test-checkSystem-zypper-assert() {
    sys_type="zypper"
    sep="-"
    @echo "$sys_type"
    @echo "$sep"
}

test-checkSystem-apt() {
    load-checkSystem
    @mock command -v yum === @false
    @mock command -v zypper === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-checkSystem-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-checkNames() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkNames
}

test-ASSERT-FAIL-checkNames-elastic-kibana-equals() {
    load-checkNames
    einame="node1"
    kiname="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-elastic-wazuh-equals() {
    load-checkNames
    einame="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-kibana-wazuh-equals() {
    load-checkNames
    kiname="node1"
    winame="node1"
    checkNames
}

test-ASSERT-FAIL-checkNames-wazuh-node-name-not-in-config() {
    load-checkNames
    winame="node1"
    wazuh_servers_node_names=(wazuh node10)
    @mock echo ${wazuh_servers_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checkNames
}

test-ASSERT-FAIL-checkNames-kibana-node-name-not-in-config() {
    load-checkNames
    kiname="node1"
    kibana_node_names=(kibana node10)
    @mock echo ${kibana_node_names[@]} === @out kibana node10
    @mock grep -w $kiname === @false
    checkNames
}

test-ASSERT-FAIL-checkNames-elasticsearch-node-name-not-in-config() {
    load-checkNames
    einame="node1"
    elasticsearch_node_names=(elasticsearch node10)
    @mock echo ${elasticsearch_node_names[@]} === @out elasticsearch node10
    @mock grep -w $einame === @false
    checkNames
}

test-checkNames-all-correct() {
    load-checkNames
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

function load-checkArch() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkArch
}

test-checkArch-x86_64() {
    @mock uname -m === @out x86_64
    load-checkArch
    checkArch
    @assert-success
}

test-ASSERT-FAIL-checkArch-empty() {
    @mock uname -m === @out
    load-checkArch
    checkArch
}

test-ASSERT-FAIL-checkArch-i386() {
    @mock uname -m === @out i386
    load-checkArch
    checkArch
}

function load-installPrerequisites() {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" installPrerequisites
}

test-installPrerequisites-yum-no-openssl() {
    @mock command -v openssl === @false
    load-installPrerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-installPrerequisites-yum-no-openssl-assert() {
    yum install curl unzip wget libcap tar gnupg openssl -y
}

test-installPrerequisites-yum() {
    @mock command -v openssl === @echo /usr/bin/openssl
    load-installPrerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-installPrerequisites-yum-assert() {
    yum install curl unzip wget libcap tar gnupg -y
}

test-installPrerequisites-zypper-no-openssl() {
    @mock command -v openssl === @false
    @mocktrue zypper -n install libcap-progs tar gnupg
    load-installPrerequisites
    sys_type="zypper"
    debug=""
    installPrerequisites
}

test-installPrerequisites-zypper-no-openssl-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap-progs tar gnupg openssl
}

test-installPrerequisites-zypper-no-libcap-progs() {
    @mock command -v openssl === @out /usr/bin/openssl
    @mockfalse zypper -n install libcap-progs tar gnupg
    load-installPrerequisites
    sys_type="zypper"
    debug=""
    installPrerequisites
}

test-installPrerequisites-zypper-no-libcap-progs-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap2 tar gnupg
}

test-installPrerequisites-apt-no-openssl() {
    @mock command -v openssl === @false
    load-installPrerequisites
    sys_type="apt-get"
    debug=""
    installPrerequisites
}

test-installPrerequisites-apt-no-openssl-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg openssl -y
}

test-installPrerequisites-apt() {
    @mock command -v openssl === @out /usr/bin/openssl
    load-installPrerequisites
    sys_type="apt-get"
    debug=""
    installPrerequisites
}

test-installPrerequisites-apt-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg -y
}

# function load-addWazuhrepo() {
#     @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" addWazuhrepo
# }

# test-addWazuhrepo-yum() {
#     load-addWazuhrepo
#     development=1
#     sys_type="yum"
#     debug=""
#     repogpg=""
#     releasever=""
#     @rm /etc/yum.repos.d/wazuh.repo
#     @rm /etc/zypp/repos.d/wazuh.repo
#     @rm /etc/apt/sources.list.d/wazuh.list
#     @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1' 
#     @mocktrue tee /etc/yum.repos.d/wazuh.repo
#     addWazuhrepo
# }

# test-addWazuhrepo-yum-assert() {
#     rm -f /etc/yum.repos.d/wazuh.repo
#     rpm --import
# }

# test-addWazuhrepo-zypper() {
#     load-addWazuhrepo
#     development=1
#     sys_type="zypper"
#     debug=""
#     repogpg=""
#     releasever=""
#     @rm /etc/yum.repos.d/wazuh.repo
#     @rm /etc/zypp/repos.d/wazuh.repo
#     @rm /etc/apt/sources.list.d/wazuh.list
#     @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1'
#     @mocktrue tee /etc/zypp/repos.d/wazuh.repo
#     addWazuhrepo
# }

# test-addWazuhrepo-zypper-assert() {
#     rm -f /etc/zypp/repos.d/wazuh.repo
#     rpm --import
# }

# test-addWazuhrepo-apt() {
#     load-addWazuhrepo
#     development=1
#     sys_type="apt-get"
#     debug=""
#     repogpg=""
#     releasever=""
#     @rm /etc/yum.repos.d/wazuh.repo
#     @rm /etc/zypp/repos.d/wazuh.repo
#     @rm /etc/apt/sources.list.d/wazuh.list
#     @mocktrue curl -s --max-time 300
#     @mocktrue apt-key add -
#     @mocktrue echo "deb /apt/  main"
#     @mocktrue tee /etc/apt/sources.list.d/wazuh.list
#     addWazuhrepo
# }

# test-addWazuhrepo-apt-assert() {
#     rm -f /etc/apt/sources.list.d/wazuh.list
#     apt-get update -q
# }

# test-addWazuhrepo-yum-file-present() {
#     load-addWazuhrepo
#     development=""
#     @touch /etc/yum.repos.d/wazuh.repo
#     @rm /etc/zypp/repos.d/wazuh.repo
#     @rm /etc/apt/sources.list.d/wazuh.list
#     addWazuhrepo
# }

# test-addWazuhrepo-zypper-file-present() {
#     load-addWazuhrepo
#     development=""
#     @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
#     @mockfalse ! -f /etc/zypp/repos.d/wazuh.repo
#     @mocktrue ! -f /etc/apt/sources.list.d/wazuh.list
#     addWazuhrepo
# }

# test-addWazuhrepo-apt-file-present() {
#     load-addWazuhrepo
#     development=""
#     @mocktrue ! -f /etc/yum.repos.d/wazuh.repo
#     @mocktrue ! -f /etc/zypp/repos.d/wazuh.repo
#     @mockfalse ! -f /etc/apt/sources.list.d/wazuh.list
#     addWazuhrepo
# }

# function load-restoreWazuhrepo() {
#     @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" restoreWazuhrepo
# }

# test-restoreWazuhrepo-no-dev() {
#     load-restoreWazuhrepo
#     development=""
#     restoreWazuhrepo
#     @assert-success
# }

# test-restoreWazuhrepo-yum() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mocktrue -f /etc/yum.repos.d/wazuh.repo
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-yum-assert() {
#     file="/etc/yum.repos.d/wazuh.repo"
#     sed -i 's/-dev//g' ${file}
#     sed -i 's/pre-release/4.x/g' ${file}
#     sed -i 's/unstable/stable/g' ${file}
# }

# test-restoreWazuhrepo-apt() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mocktrue -f /etc/apt/sources.list.d/wazuh.list
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-apt-assert() {
#     file="/etc/apt/sources.list.d/wazuh.list"
#     sed -i 's/-dev//g' ${file}
#     sed -i 's/pre-release/4.x/g' ${file}
#     sed -i 's/unstable/stable/g' ${file}
# }

# test-restoreWazuhrepo-zypper() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mocktrue -f /etc/zypp/repos.d/wazuh.repo
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-zypper-assert() {
#     file="/etc/zypp/repos.d/wazuh.repo"
#     sed -i 's/-dev//g' ${file}
#     sed -i 's/pre-release/4.x/g' ${file}
#     sed -i 's/unstable/stable/g' ${file}
# }

# test-restoreWazuhrepo-yum-no-file() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mockfalse -f /etc/yum.repos.d/wazuh.repo
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-yum-assert() {
#     sed -i 's/-dev//g'
#     sed -i 's/pre-release/4.x/g'
#     sed -i 's/unstable/stable/g'
# }

# test-restoreWazuhrepo-apt-no-file() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mockfalse -f /etc/apt/sources.list.d/wazuh.list
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-apt-assert() {
#     sed -i 's/-dev//g'
#     sed -i 's/pre-release/4.x/g'
#     sed -i 's/unstable/stable/g'
# }

# test-restoreWazuhrepo-zypper() {
#     load-restoreWazuhrepo
#     development="1"
#     sys_type="yum"
#     #@mockfalse -f /etc/zypp/repos.d/wazuh.repo
#     restoreWazuhrepo
# }

# test-restoreWazuhrepo-zypper-assert() {
#     file="/etc/zypp/repos.d/wazuh.repo"
#     sed -i 's/-dev//g'
#     sed -i 's/pre-release/4.x/g'
#     sed -i 's/unstable/stable/g'
# }

function load-checkArguments {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-certs-file-present() {
    load-checkArguments
    AIO=1
    base_path=/tmp
    @mkdir ${base_path}/certs
    checkArguments
}

test-ASSERT-FAIL-checkArguments-certificate-creation-certs-file-present() {
    load-checkArguments
    certificates=1
    base_path=/tmp
    @mkdir ${base_path}/certs
    checkArguments
}

test-ASSERT-FAIL-checkArguments-overwrite-with-no-component-installed() {
    load-checkArguments
    overwrite=1
    AIO=
    elasticsearch=
    wazuh=
    kibana=
    checkArguments
}

test-checkArguments-uninstall-no-component-installed() {
    load-checkArguments
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
    @assert-success
}

test-ASSERT-FAIL-checkArguments-uninstall-and-aio() {
    load-checkArguments
    uninstall=1
    AIO=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-wazuh() {
    load-checkArguments
    uninstall=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-kibana() {
    load-checkArguments
    uninstall=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-uninstall-and-elasticsearch() {
    load-checkArguments
    uninstall=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-elastic () {
    load-checkArguments
    AIO=1
    elasticsearch=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-wazuh () {
    load-checkArguments
    AIO=1
    wazuh=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-and-kibana () {
    load-checkArguments
    AIO=1
    kibana=1
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-wazuh-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-wazuh-files-no-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-elastic-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-elastic-files-no-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-kibana-installed-no-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-aio-kibana-files-no-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-aio-wazuh-installed-overwrite() {
    load-checkArguments
    AIO=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-wazuh-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-wazuh-files-overwrite() {
    load-checkArguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-wazuh-files-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-elastic-installed-overwrite() {
    load-checkArguments
    AIO=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-elastic-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-elastic-files-overwrite() {
    load-checkArguments
    AIO=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-elastic-files-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-kibana-installed-overwrite() {
    load-checkArguments
    AIO=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-kibana-installed-overwrite-assert() {
    rollBack
}

test-checkArguments-install-aio-kibana-files-overwrite() {
    load-checkArguments
    AIO=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-aio-kibana-files-overwrite-assert() {
    rollBack
}

test-ASSERT-FAIL-checkArguments-install-elastic-already-installed-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-elastic-remaining-files-no-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-elastic-already-installed-overwrite() {
    load-checkArguments
    elasticsearch=1
    elasticsearchinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-elastic-already-installed-overwrite-assert() {
    rollBack elasticsearch
}

test-checkArguments-install-elastic-remaining-files-overwrite() {
    load-checkArguments
    elasticsearch=1
    elastic_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-elastic-remaining-files-overwrite-assert() {
    rollBack elasticsearch
}

test-ASSERT-FAIL-checkArguments-install-wazuh-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-wazuh-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-wazuh-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    wazuhinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-already-installed-overwrite-assert() {
    rollBack wazuh
}

test-checkArguments-install-wazuh-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-remaining-files-overwrite-assert() {
    rollBack wazuh
}

test-ASSERT-FAIL-checkArguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-already-installed-overwrite() {
    load-checkArguments
    wazuh=1
    filebeatinstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-already-installed-overwrite-assert() {
    rollBack filebeat
}

test-checkArguments-install-wazuh-filebeat-remaining-files-overwrite() {
    load-checkArguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-wazuh-filebeat-remaining-files-overwrite-assert() {
    rollBack filebeat
}

test-ASSERT-FAIL-checkArguments-install-kibana-already-installed-no-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=
    checkArguments
}

test-ASSERT-FAIL-checkArguments-install-kibana-remaining-files-no-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=
    checkArguments
}

test-checkArguments-install-kibana-already-installed-overwrite() {
    load-checkArguments
    kibana=1
    kibanainstalled=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-kibana-already-installed-overwrite-assert() {
    rollBack kibana
}

test-checkArguments-install-kibana-remaining-files-overwrite() {
    load-checkArguments
    kibana=1
    kibana_remaining_files=1
    overwrite=1
    checkArguments
}

test-checkArguments-install-kibana-remaining-files-overwrite-assert() {
    rollBack kibana
}

function load-createClusterKey {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" createClusterKey
}

test-createClusterKey() {
    load-createClusterKey
    base_path=/tmp
    @mocktrue openssl rand -hex 16 >> /tmp/certs/clusterkey
    createClusterKey
    @assert-success
}

function load-rollBack {
    @load_function "${base_dir}/unattended_scripts/install_functions/opendistro/common.sh" rollBack
}

test-rollBack-no-arguments-all-installed-yum() {
    load-rollBack
    elasticsearchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys-type="yum"
    debug=
    rollBack
}

test-rollBack-no-arguments-all-installed-yum-assert() {
    yum remove wazuh-manager -y
    rm -rf /var/ossec/
    yum remove opendistroforelasticsearch -y
    yum remove elasticsearch* -y
    yum remove opendistro-* -y
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    yum remove filebeat -y
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    yum remove opendistroforelasticsearch-kibana -y
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/
}