#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-common_getConfig() {
    @load_function "${base_dir}/common.sh" common_getConfig
}

test-ASSERT-FAIL-01-common_getConfig-no-args() {
    load-common_getConfig
    common_getConfig
}

test-ASSERT-FAIL-02-common_getConfig-one-argument() {
    load-common_getConfig
    common_getConfig "elasticsearch"
}

test-03-common_getConfig-local() {
    load-common_getConfig
    base_path="/tmp"
    config_path="example"
    local=1
    common_getConfig opensearch.yml /tmp/elasticsearch/opensearch.yml
}

test-03-common_getConfig-local-assert() {
    cp /tmp/example/opensearch.yml /tmp/elasticsearch/opensearch.yml
}

test-04-common_getConfig-online() {
    load-common_getConfig
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
    common_getConfig opensearch.yml /tmp/elasticsearch/opensearch.yml
}

test-04-common_getConfig-online-assert() {
    curl -f -so /tmp/elasticsearch/opensearch.yml example.com/config/opensearch.yml
}

test-05-common_getConfig-local-error() {
    load-common_getConfig
    base_path="/tmp"
    config_path="example"
    local=1
    @mockfalse cp /tmp/example/opensearch.yml /tmp/elasticsearch/opensearch.yml
    common_getConfig opensearch.yml /tmp/elasticsearch/opensearch.yml
}

test-05-common_getConfig-local-error-assert() {
    common_rollBack
    exit 1
}

test-06-common_getConfig-online-error() {
    load-common_getConfig
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
    @mockfalse curl -f -so /tmp/elasticsearch/opensearch.yml example.com/config/opensearch.yml
    common_getConfig opensearch.yml /tmp/elasticsearch/opensearch.yml
}

test-06-common_getConfig-online-error-assert() {
    common_rollBack
    exit 1
}

function load-common_installPrerequisites() {
    @load_function "${base_dir}/common.sh" common_installPrerequisites
}

test-07-common_installPrerequisites-yum-no-openssl() {
    @mock command -v openssl === @false
    load-common_installPrerequisites
    sys_type="yum"
    debug=""
    common_installPrerequisites
}

test-07-common_installPrerequisites-yum-no-openssl-assert() {
    yum install curl unzip wget libcap tar gnupg openssl -y
}

test-08-common_installPrerequisites-yum() {
    @mock command -v openssl === @echo /usr/bin/openssl
    load-common_installPrerequisites
    sys_type="yum"
    debug=""
    common_installPrerequisites
}

test-08-common_installPrerequisites-yum-assert() {
    yum install curl unzip wget libcap tar gnupg -y
}

test-09-common_installPrerequisites-zypper-no-openssl() {
    @mock command -v openssl === @false
    @mocktrue zypper -n install libcap-progs tar gnupg
    load-common_installPrerequisites
    sys_type="zypper"
    debug=""
    common_installPrerequisites
}

test-09-common_installPrerequisites-zypper-no-openssl-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap-progs tar gnupg openssl
}

test-10-common_installPrerequisites-zypper-no-libcap-progs() {
    @mock command -v openssl === @out /usr/bin/openssl
    @mockfalse zypper -n install libcap-progs tar gnupg
    load-common_installPrerequisites
    sys_type="zypper"
    debug=""
    common_installPrerequisites
}

test-10-common_installPrerequisites-zypper-no-libcap-progs-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap2 tar gnupg
}

test-11-common_installPrerequisites-apt-no-openssl() {
    @mock command -v openssl === @false
    load-common_installPrerequisites
    sys_type="apt-get"
    debug=""
    common_installPrerequisites
}

test-11-common_installPrerequisites-apt-no-openssl-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg openssl -y
}

test-12-common_installPrerequisites-apt() {
    @mock command -v openssl === @out /usr/bin/openssl
    load-common_installPrerequisites
    sys_type="apt-get"
    debug=""
    common_installPrerequisites
}

test-12-common_installPrerequisites-apt-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg -y
}

function load-common_addWazuhRepo() {
    @load_function "${base_dir}/common.sh" common_addWazuhRepo
}

test-13-common_addWazuhRepo-yum() {
    load-common_addWazuhRepo
    development=1
    sys_type="yum"
    debug=""
    repogpg=""
    releasever=""
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1'
    @mocktrue tee /etc/yum.repos.d/wazuh.repo
    common_addWazuhRepo
}

test-13-common_addWazuhRepo-yum-assert() {
    rm -f /etc/yum.repos.d/wazuh.repo
    rpm --import
}

test-14-common_addWazuhRepo-zypper() {
    load-common_addWazuhRepo
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
    common_addWazuhRepo
}

test-14-common_addWazuhRepo-zypper-assert() {
    rm -f /etc/zypp/repos.d/wazuh.repo
    rpm --import
}

test-15-common_addWazuhRepo-apt() {
    load-common_addWazuhRepo
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
    common_addWazuhRepo
}

test-15-common_addWazuhRepo-apt-assert() {
    rm -f /etc/apt/sources.list.d/wazuh.list
    apt-get update -q
}

test-16-common_addWazuhRepo-apt-file-present() {
    load-common_addWazuhRepo
    development=""
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    common_addWazuhRepo
    @assert-success
    @rm /etc/yum.repos.d/wazuh.repo
}

test-17-common_addWazuhRepo-zypper-file-present() {
    load-common_addWazuhRepo
    development=""
    @mkdir -p /etc/zypp/repos.d/
    @touch /etc/zypp/repos.d/wazuh.repo
    common_addWazuhRepo
    @assert-success
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-18-common_addWazuhRepo-yum-file-present() {
    load-common_addWazuhRepo
    development=""
    @mkdir -p /etc/apt/sources.list.d/
    @touch /etc/apt/sources.list.d/wazuh.list
    common_addWazuhRepo
    @assert-success
    @rm /etc/apt/sources.list.d/wazuh.list
}

function load-common_restoreWazuhrepo() {
    @load_function "${base_dir}/common.sh" common_restoreWazuhrepo
}

test-19-common_restoreWazuhrepo-no-dev() {
    load-common_restoreWazuhrepo
    development=""
    common_restoreWazuhrepo
    @assert-success
}

test-20-common_restoreWazuhrepo-yum() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="yum"
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    common_restoreWazuhrepo
    @rm /etc/yum.repos.d/wazuh.repo
}

test-20-common_restoreWazuhrepo-yum-assert() {
    sed -i 's/-dev//g' /etc/yum.repos.d/wazuh.repo
    sed -i 's/pre-release/4.x/g' /etc/yum.repos.d/wazuh.repo
    sed -i 's/unstable/stable/g' /etc/yum.repos.d/wazuh.repo
}

test-21-common_restoreWazuhrepo-apt() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="apt-get"
    @mkdir -p /etc/apt/sources.list.d/
    @touch /etc/apt/sources.list.d/wazuh.list
    common_restoreWazuhrepo
    @rm /etc/apt/sources.list.d/wazuh.list
}

test-21-common_restoreWazuhrepo-apt-assert() {
    sed -i 's/-dev//g' /etc/apt/sources.list.d/wazuh.list
    sed -i 's/pre-release/4.x/g' /etc/apt/sources.list.d/wazuh.list
    sed -i 's/unstable/stable/g' /etc/apt/sources.list.d/wazuh.list
}

test-22-common_restoreWazuhrepo-zypper() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="zypper"
    @mkdir -p /etc/zypp/repos.d/
    @touch /etc/zypp/repos.d/wazuh.repo
    common_restoreWazuhrepo
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-22-common_restoreWazuhrepo-zypper-assert() {
    sed -i 's/-dev//g' /etc/zypp/repos.d/wazuh.repo
    sed -i 's/pre-release/4.x/g' /etc/zypp/repos.d/wazuh.repo
    sed -i 's/unstable/stable/g' /etc/zypp/repos.d/wazuh.repo
}

test-23-common_restoreWazuhrepo-yum-no-file() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="yum"
    common_restoreWazuhrepo
}

test-23-common_restoreWazuhrepo-yum-no-file-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-24-common_restoreWazuhrepo-apt-no-file() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="yum"
    common_restoreWazuhrepo
}

test-24-common_restoreWazuhrepo-apt-no-file-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-25-common_restoreWazuhrepo-zypper-no-file() {
    load-common_restoreWazuhrepo
    development="1"
    sys_type="yum"
    common_restoreWazuhrepo
}

test-25-common_restoreWazuhrepo-zypper-no-file-assert() {
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

function load-common_createClusterKey {
    @load_function "${base_dir}/common.sh" common_createClusterKey
}

test-26-common_createClusterKey() {
    load-common_createClusterKey
    base_path=/tmp
    @mkdir -p /tmp/certs
    @touch /tmp/certs/clusterkey
    @mocktrue openssl rand -hex 16
    common_createClusterKey
    @assert-success
    @rm /tmp/certs/clusterkey
}

function load-common_rollBack {
    @load_function "${base_dir}/common.sh" common_rollBack
}

test-27-common_rollBack-aio-all-installed-yum() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="yum"
    debug=
    AIO=1
    common_rollBack
}

test-27-common_rollBack-aio-all-installed-yum-assert() {
    yum remove wazuh-manager -y
    
    rm -rf /var/ossec/
    
    yum remove opendistroforelasticsearch -y
    yum remove elasticsearch* -y
    yum remove opendistro-* -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    yum remove filebeat -y
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    yum remove opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm  -rf  /var/log/elasticsearch/  /var/log/filebeat/  /etc/systemd/system/elasticsearch.service.wants/  /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service  /lib/firewalld/services/kibana.xml  /lib/firewalld/services/elasticsearch.xml
}

test-28-common_rollBack-aio-all-installed-zypper() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="zypper"
    debug=
    AIO=1
    common_rollBack
}

test-28-common_rollBack-aio-all-installed-zypper-assert() {
    zypper -n remove wazuh-manager
    rm -f /etc/init.d/wazuh-manager
    
    rm -rf /var/ossec/
    
    zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-*
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    zypper -n remove filebeat
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    zypper -n remove opendistroforelasticsearch-kibana
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-29-common_rollBack-aio-all-installed-apt() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="apt-get"
    debug=
    AIO=1
    common_rollBack
}

test-29-common_rollBack-aio-all-installed-apt-assert() {
    apt remove --purge wazuh-manager -y
    
    rm -rf /var/ossec/
    
    apt remove --purge ^elasticsearch* ^opendistro-* ^opendistroforelasticsearch -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    apt remove --purge filebeat -y
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    apt remove --purge opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-30-common_rollBack-elasticsearch-installation-all-installed-yum() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="yum"
    debug=
    elasticsearch=1
    common_rollBack
}

test-30-common_rollBack-elasticsearch-installation-all-installed-yum-assert() {
    yum remove opendistroforelasticsearch -y
    yum remove elasticsearch* -y
    yum remove opendistro-* -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-31-common_rollBack-elasticsearch-installation-all-installed-zypper() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="zypper"
    debug=
    elasticsearch=1
    common_rollBack
}

test-31-common_rollBack-elasticsearch-installation-all-installed-zypper-assert() {
    zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-*
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-32-common_rollBack-elasticsearch-installation-all-installed-apt() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="apt-get"
    debug=
    elasticsearch=1
    common_rollBack
}

test-32-common_rollBack-elasticsearch-installation-all-installed-apt-assert() {
    apt remove --purge ^elasticsearch* ^opendistro-* ^opendistroforelasticsearch -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-33-common_rollBack-wazuh-installation-all-installed-yum() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="yum"
    debug=
    wazuh=1
    common_rollBack
}

test-33-common_rollBack-wazuh-installation-all-installed-yum-assert() {
    yum remove wazuh-manager -y
    
    rm -rf /var/ossec/

    yum remove filebeat -y 

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-34-common_rollBack-wazuh-installation-all-installed-zypper() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="zypper"
    debug=
    wazuh=1
    common_rollBack
}

test-34-common_rollBack-wazuh-installation-all-installed-zypper-assert() {
    zypper -n remove wazuh-manager
    rm -f /etc/init.d/wazuh-manager
    
    rm -rf /var/ossec/

    zypper -n remove filebeat

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-35-common_rollBack-wazuh-installation-all-installed-apt() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="apt-get"
    debug=
    wazuh=1
    common_rollBack
}

test-35-common_rollBack-wazuh-installation-all-installed-apt-assert() {
    apt remove --purge wazuh-manager -y
    
    rm -rf /var/ossec/

    apt remove --purge filebeat -y

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-36-common_rollBack-kibana-installation-all-installed-yum() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="yum"
    debug=
    kibana=1
    common_rollBack
}

test-36-common_rollBack-kibana-installation-all-installed-yum-assert() {
    yum remove opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-37-common_rollBack-kibana-installation-all-installed-zypper() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="zypper"
    debug=
    kibana=1
    common_rollBack
}

test-37-common_rollBack-kibana-installation-all-installed-zypper-assert() {
    zypper -n remove opendistroforelasticsearch-kibana
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-38-common_rollBack-kibana-installation-all-installed-apt() {
    load-common_rollBack
    indexerchinstalled=1
    wazuhinstalled=1
    kibanainstalled=1
    filebeatinstalled=1
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="apt-get"
    debug=
    kibana=1
    common_rollBack
}

test-38-common_rollBack-kibana-installation-all-installed-apt-assert() {
    apt remove --purge opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-39-common_rollBack-aio-nothing-installed() {
    load-common_rollBack
    indexerchinstalled=
    wazuhinstalled=
    kibanainstalled=
    filebeatinstalled=
    wazuh_remaining_files=
    elastic_remaining_files=
    kibana_remaining_files=
    filebeat_remaining_files=
    sys_type="yum"
    debug=
    AIO=1
    common_rollBack
    @assert-success
}

test-40-common_rollBack-aio-all-remaining-files-yum() {
    load-common_rollBack
    indexerchinstalled=
    wazuhinstalled=
    kibanainstalled=
    filebeatinstalled=
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="yum"
    debug=
    AIO=1
    common_rollBack
}

test-40-common_rollBack-aio-all-remaining-files-yum-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-41-common_rollBack-aio-all-remaining-files-zypper() {
    load-common_rollBack
    indexerchinstalled=
    wazuhinstalled=
    kibanainstalled=
    filebeatinstalled=
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="zypper"
    debug=
    AIO=1
    common_rollBack
}

test-41-common_rollBack-aio-all-remaining-files-zypper-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-42-common_rollBack-aio-all-remaining-files-apt() {
    load-common_rollBack
    indexerchinstalled=
    wazuhinstalled=
    kibanainstalled=
    filebeatinstalled=
    wazuh_remaining_files=1
    elastic_remaining_files=1
    kibana_remaining_files=1
    filebeat_remaining_files=1
    sys_type="apt-get"
    debug=
    AIO=1
    common_rollBack
}

test-42-common_rollBack-aio-all-remaining-files-apt-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/wazuh-indexer/
    rm -rf /etc/wazuh-indexer/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-43-common_rollBack-nothing-installed-remove-yum-repo() {
    load-common_rollBack
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    common_rollBack
    @rm /etc/yum.repos.d/wazuh.repo
}

test-43-common_rollBack-nothing-installed-remove-yum-repo-assert() {
    rm /etc/yum.repos.d/wazuh.repo

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-44-common_rollBack-nothing-installed-remove-zypper-repo() {
    load-common_rollBack
    @mkdir -p /etc/zypp/repos.d
    @touch /etc/zypp/repos.d/wazuh.repo
    common_rollBack
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-44-common_rollBack-nothing-installed-remove-zypper-repo-assert() {
    rm /etc/zypp/repos.d/wazuh.repo

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-45-common_rollBack-nothing-installed-remove-apt-repo() {
    load-common_rollBack
    @mkdir -p /etc/apt/sources.list.d
    @touch /etc/apt/sources.list.d/wazuh.list
    common_rollBack
    @rm /etc/apt/sources.list.d/wazuh.list
}

test-45-common_rollBack-nothing-installed-remove-apt-repo-assert() {
    rm /etc/apt/sources.list.d/wazuh.list

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml

}

test-46-common_rollBack-nothing-installed-remove-files() {
    load-common_rollBack
    @mkdir -p /var/log/elasticsearch/
    common_rollBack
    @rmdir /var/log/elasticsearch
}

test-46-common_rollBack-nothing-installed-remove-files-assert() {
    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh /etc/systemd/system/multi-user.target.wants/wazuh-manager.service /etc/systemd/system/multi-user.target.wants/filebeat.service /etc/systemd/system/multi-user.target.wants/elasticsearch.service /etc/systemd/system/multi-user.target.wants/kibana.service /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

function load-common_createCertificates() {
    @load_function "${base_dir}/common.sh" common_createCertificates
}

test-47-common_createCertificates-aio() {
    load-common_createCertificates
    AIO=1
    base_path=/tmp
    common_createCertificates
}

test-47-common_createCertificates-aio-assert() {
    common_getConfig certificate/config_aio.yml /tmp/config.yml

    readConfig

    mkdir /tmp/certs

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

test-48-common_createCertificates-no-aio() {
    load-common_createCertificates
    base_path=/tmp
    common_createCertificates
}

test-48-common_createCertificates-no-aio-assert() {

    readConfig

    mkdir /tmp/certs

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

function load-common_changePasswords() {
    @load_function "${base_dir}/common.sh" common_changePasswords
}

test-ASSERT-FAIL-49-common_changePasswords-no-tarfile() {
    load-common_changePasswords
    tar_file=
    common_changePasswords
}

test-50-common_changePasswords-with-tarfile() {
    load-common_changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    common_changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-50-common_changePasswords-with-tarfile-assert() {
    checkInstalledPass
    common_readPasswordFileUsers
    changePassword
    rm -rf /tmp/password_file.yml
    @echo 
}

test-51-common_changePasswords-with-tarfile-aio() {
    load-common_changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    AIO=1
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    common_changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-51-common_changePasswords-with-tarfile-aio-assert() {
    checkInstalledPass
    readUsers
    common_readPasswordFileUsers
    getNetworkHost
    createBackUp
    generateHash
    changePassword
    runSecurityAdmin
    rm -rf /tmp/password_file.yml
    @echo 1
}

test-52-common_changePasswords-with-tarfile-start-elastic-cluster() {
    load-common_changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    AIO=1
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    common_changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-52-common_changePasswords-with-tarfile-start-elastic-cluster-assert() {
    checkInstalledPass
    readUsers
    common_readPasswordFileUsers
    getNetworkHost
    createBackUp
    generateHash
    changePassword
    runSecurityAdmin
    rm -rf /tmp/password_file.yml
    @echo 1
}

function load-common_getPass() {
    @load_function "${base_dir}/common.sh" common_getPass
}

test-53-common_getPass-no-args() {
    load-common_getPass
    users=(kibanaserver admin)
    passwords=(kibanaserver_pass admin_pass)
    common_getPass
    @echo $u_pass
}

test-53-common_getPass-no-args-assert() {
    @echo
}

test-54-common_getPass-admin() {
    load-common_getPass
    users=(kibanaserver admin)
    passwords=(kibanaserver_pass admin_pass)
    common_getPass admin
    @echo $u_pass
}

test-54-common_getPass-admin-assert() {
    @echo admin_pass
}

function load-common_startService() {
    @load_function "${base_dir}/common.sh" common_startService
}

test-ASSERT-FAIL-55-common_startService-no-args() {
    load-common_startService
    common_startService
}

test-ASSERT-FAIL-56-common_startService-no-service-manager() {
    load-common_startService
    @mockfalse ps -e
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @rm /etc/init.d/wazuh
    common_startService wazuh-manager
}

test-57-common_startService-systemd() {
    load-common_startService
    @mockfalse ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    common_startService wazuh-manager
}

test-57-common_startService-systemd-assert() {
    systemctl daemon-reload
    systemctl enable wazuh-manager.service
    systemctl start wazuh-manager.service
}

test-58-common_startService-systemd-error() {
    load-common_startService
    @mock ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @mockfalse systemctl start wazuh-manager.service
    common_startService wazuh-manager
}

test-58-common_startService-systemd-error-assert() {
    systemctl daemon-reload
    systemctl enable wazuh-manager.service
    common_rollBack
    exit 1
}

test-59-common_startService-initd() {
    load-common_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    common_startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-59-common_startService-initd-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    chkconfig wazuh-manager on
    service wazuh-manager start
    /etc/init.d/wazuh-manager start
    @rm /etc/init.d/wazuh-manager
}

test-60-common_startService-initd-error() {
    load-common_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    #/etc/init.d/wazuh-manager is not executable -> It will fail
    common_startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-60-common_startService-initd-error-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    chkconfig wazuh-manager on
    service wazuh-manager start
    /etc/init.d/wazuh-manager start
    common_rollBack
    exit 1
    @rm /etc/init.d/wazuh-manager
}

test-61-common_startService-rc.d/init.d() {
    load-common_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"

    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager

    common_startService wazuh-manager
    @rm /etc/rc.d/init.d/wazuh-manager
}

test-61-common_startService-rc.d/init.d-assert() {
    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager
    /etc/rc.d/init.d/wazuh-manager start
    @rm /etc/rc.d/init.d/wazuh-manager
}

function load-common_readPasswordFileUsers() {
    @load_function "${base_dir}/common.sh" common_readPasswordFileUsers
}

test-ASSERT-FAIL-62-common_readPasswordFileUsers-file-incorrect() {
    load-common_readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 0
    common_readPasswordFileUsers
}

test-63-common_readPasswordFileUsers-changeall-correct() {
    load-common_readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @echo wazuh kibanaserver
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @echo wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    common_readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-63-common_readPasswordFileUsers-changeall-correct-assert() {
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-64-common_readPasswordFileUsers-changeall-user-doesnt-exist() {
    load-common_readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    common_readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-64-common_readPasswordFileUsers-changeall-user-doesnt-exist-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-65-common_readPasswordFileUsers-no-changeall-kibana-correct() {
    load-common_readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword adminpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=
    kibanainstalled=1
    kibana=1
    common_readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-65-common_readPasswordFileUsers-no-changeall-kibana-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo kibanaserver admin
    @echo kibanaserverpassword adminpassword
}

test-66-common_readPasswordFileUsers-no-changeall-filebeat-correct() {
    load-common_readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword adminpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=
    filebeatinstalled=1
    wazuh=1
    common_readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-66-common_readPasswordFileUsers-no-changeall-filebeat-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo admin
    @echo adminpassword
}

