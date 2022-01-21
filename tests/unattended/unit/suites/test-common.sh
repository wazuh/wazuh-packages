#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
}

function load-getConfig() {
    @load_function "${base_dir}/common.sh" getConfig
}

test-ASSERT-FAIL-01-getConfig-no-args() {
    load-getConfig
    getConfig
}

test-ASSERT-FAIL-02-getConfig-one-argument() {
    load-getConfig
    getConfig "elasticsearch"
}

test-03-getConfig-local() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    local=1
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-03-getConfig-local-assert() {
    cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-04-getConfig-online() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-04-getConfig-online-assert() {
    curl -f -so /tmp/elasticsearch/elasticsearch.yml example.com/config/elasticsearch.yml
}

test-05-getConfig-local-error() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    local=1
    @mockfalse cp /tmp/example/elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-05-getConfig-local-error-assert() {
    rollBack
    exit 1
}

test-06-getConfig-online-error() {
    load-getConfig
    base_path="/tmp"
    config_path="example"
    resources_config="example.com/config"
    local=
    @mockfalse curl -f -so /tmp/elasticsearch/elasticsearch.yml example.com/config/elasticsearch.yml
    getConfig elasticsearch.yml /tmp/elasticsearch/elasticsearch.yml
}

test-06-getConfig-online-error-assert() {
    rollBack
    exit 1
}

function load-installPrerequisites() {
    @load_function "${base_dir}/common.sh" installPrerequisites
}

test-07-installPrerequisites-yum-no-openssl() {
    @mock command -v openssl === @false
    load-installPrerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-07-installPrerequisites-yum-no-openssl-assert() {
    yum install curl unzip wget libcap tar gnupg openssl -y
}

test-08-installPrerequisites-yum() {
    @mock command -v openssl === @echo /usr/bin/openssl
    load-installPrerequisites
    sys_type="yum"
    debug=""
    installPrerequisites
}

test-08-installPrerequisites-yum-assert() {
    yum install curl unzip wget libcap tar gnupg -y
}

test-09-installPrerequisites-zypper-no-openssl() {
    @mock command -v openssl === @false
    @mocktrue zypper -n install libcap-progs tar gnupg
    load-installPrerequisites
    sys_type="zypper"
    debug=""
    installPrerequisites
}

test-09-installPrerequisites-zypper-no-openssl-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap-progs tar gnupg openssl
}

test-10-installPrerequisites-zypper-no-libcap-progs() {
    @mock command -v openssl === @out /usr/bin/openssl
    @mockfalse zypper -n install libcap-progs tar gnupg
    load-installPrerequisites
    sys_type="zypper"
    debug=""
    installPrerequisites
}

test-10-installPrerequisites-zypper-no-libcap-progs-assert() {
    zypper -n install curl unzip wget
    zypper -n install libcap2 tar gnupg
}

test-11-installPrerequisites-apt-no-openssl() {
    @mock command -v openssl === @false
    load-installPrerequisites
    sys_type="apt-get"
    debug=""
    installPrerequisites
}

test-11-installPrerequisites-apt-no-openssl-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg openssl -y
}

test-12-installPrerequisites-apt() {
    @mock command -v openssl === @out /usr/bin/openssl
    load-installPrerequisites
    sys_type="apt-get"
    debug=""
    installPrerequisites
}

test-12-installPrerequisites-apt-assert() {
    apt-get update -q
    apt-get install apt-transport-https curl unzip wget libcap2-bin tar gnupg -y
}

function load-addWazuhrepo() {
    @load_function "${base_dir}/common.sh" addWazuhrepo
}

test-13-addWazuhrepo-yum() {
    load-addWazuhrepo
    development=1
    sys_type="yum"
    debug=""
    repogpg=""
    releasever=""
    @mocktrue echo -e '[wazuh]\ngpgcheck=1\ngpgkey=\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=/yum/\nprotect=1'
    @mocktrue tee /etc/yum.repos.d/wazuh.repo
    addWazuhrepo
}

test-13-addWazuhrepo-yum-assert() {
    rm -f /etc/yum.repos.d/wazuh.repo
    rpm --import
}

test-14-addWazuhrepo-zypper() {
    load-addWazuhrepo
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

test-14-addWazuhrepo-zypper-assert() {
    rm -f /etc/zypp/repos.d/wazuh.repo
    rpm --import
}

test-15-addWazuhrepo-apt() {
    load-addWazuhrepo
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

test-15-addWazuhrepo-apt-assert() {
    rm -f /etc/apt/sources.list.d/wazuh.list
    apt-get update -q
}

test-16-addWazuhrepo-apt-file-present() {
    load-addWazuhrepo
    development=""
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    addWazuhrepo
    @assert-success
    @rm /etc/yum.repos.d/wazuh.repo
}

test-17-addWazuhrepo-zypper-file-present() {
    load-addWazuhrepo
    development=""
    @mkdir -p /etc/zypp/repos.d/
    @touch /etc/zypp/repos.d/wazuh.repo
    addWazuhrepo
    @assert-success
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-18-addWazuhrepo-yum-file-present() {
    load-addWazuhrepo
    development=""
    @mkdir -p /etc/apt/sources.list.d/
    @touch /etc/apt/sources.list.d/wazuh.list
    addWazuhrepo
    @assert-success
    @rm /etc/apt/sources.list.d/wazuh.list
}

function load-restoreWazuhrepo() {
    @load_function "${base_dir}/common.sh" restoreWazuhrepo
}

test-19-restoreWazuhrepo-no-dev() {
    load-restoreWazuhrepo
    development=""
    restoreWazuhrepo
    @assert-success
}

test-20-restoreWazuhrepo-yum() {
    load-restoreWazuhrepo
    development="1"
    sys_type="yum"
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    restoreWazuhrepo
    @rm /etc/yum.repos.d/wazuh.repo
}

test-20-restoreWazuhrepo-yum-assert() {
    sed -i 's/-dev//g' /etc/yum.repos.d/wazuh.repo
    sed -i 's/pre-release/4.x/g' /etc/yum.repos.d/wazuh.repo
    sed -i 's/unstable/stable/g' /etc/yum.repos.d/wazuh.repo
}

test-21-restoreWazuhrepo-apt() {
    load-restoreWazuhrepo
    development="1"
    sys_type="apt-get"
    @mkdir -p /etc/apt/sources.list.d/
    @touch /etc/apt/sources.list.d/wazuh.list
    restoreWazuhrepo
    @rm /etc/apt/sources.list.d/wazuh.list
}

test-21-restoreWazuhrepo-apt-assert() {
    sed -i 's/-dev//g' /etc/apt/sources.list.d/wazuh.list
    sed -i 's/pre-release/4.x/g' /etc/apt/sources.list.d/wazuh.list
    sed -i 's/unstable/stable/g' /etc/apt/sources.list.d/wazuh.list
}

test-22-restoreWazuhrepo-zypper() {
    load-restoreWazuhrepo
    development="1"
    sys_type="zypper"
    @mkdir -p /etc/zypp/repos.d/
    @touch /etc/zypp/repos.d/wazuh.repo
    restoreWazuhrepo
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-22-restoreWazuhrepo-zypper-assert() {
    sed -i 's/-dev//g' /etc/zypp/repos.d/wazuh.repo
    sed -i 's/pre-release/4.x/g' /etc/zypp/repos.d/wazuh.repo
    sed -i 's/unstable/stable/g' /etc/zypp/repos.d/wazuh.repo
}

test-23-restoreWazuhrepo-yum-no-file() {
    load-restoreWazuhrepo
    development="1"
    sys_type="yum"
    restoreWazuhrepo
}

test-23-restoreWazuhrepo-yum-no-file-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-24-restoreWazuhrepo-apt-no-file() {
    load-restoreWazuhrepo
    development="1"
    sys_type="yum"
    restoreWazuhrepo
}

test-24-restoreWazuhrepo-apt-no-file-assert() {
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

test-25-restoreWazuhrepo-zypper-no-file() {
    load-restoreWazuhrepo
    development="1"
    sys_type="yum"
    restoreWazuhrepo
}

test-25-restoreWazuhrepo-zypper-no-file-assert() {
    file="/etc/zypp/repos.d/wazuh.repo"
    sed -i 's/-dev//g'
    sed -i 's/pre-release/4.x/g'
    sed -i 's/unstable/stable/g'
}

function load-createClusterKey {
    @load_function "${base_dir}/common.sh" createClusterKey
}

test-26-createClusterKey() {
    load-createClusterKey
    base_path=/tmp
    @mkdir -p /tmp/certs
    @touch /tmp/certs/clusterkey
    @mocktrue openssl rand -hex 16
    createClusterKey
    @assert-success
    @rm /tmp/certs/clusterkey
}

function load-rollBack {
    @load_function "${base_dir}/common.sh" rollBack
}

test-27-rollBack-aio-all-installed-yum() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-27-rollBack-aio-all-installed-yum-assert() {
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

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-28-rollBack-aio-all-installed-zypper() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-28-rollBack-aio-all-installed-zypper-assert() {
    zypper -n remove wazuh-manager
    rm -f /etc/init.d/wazuh-manager
    
    rm -rf /var/ossec/
    
    zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-*
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    
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

test-29-rollBack-aio-all-installed-apt() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-29-rollBack-aio-all-installed-apt-assert() {
    apt remove --purge wazuh-manager -y
    
    rm -rf /var/ossec/
    
    apt remove --purge ^elasticsearch* ^opendistro-* ^opendistroforelasticsearch -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    
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

test-30-rollBack-elasticsearch-installation-all-installed-yum() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-30-rollBack-elasticsearch-installation-all-installed-yum-assert() {
    yum remove opendistroforelasticsearch -y
    yum remove elasticsearch* -y
    yum remove opendistro-* -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-31-rollBack-elasticsearch-installation-all-installed-zypper() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-31-rollBack-elasticsearch-installation-all-installed-zypper-assert() {
    zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-*
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-32-rollBack-elasticsearch-installation-all-installed-apt() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-32-rollBack-elasticsearch-installation-all-installed-apt-assert() {
    apt remove --purge ^elasticsearch* ^opendistro-* ^opendistroforelasticsearch -y
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-33-rollBack-wazuh-installation-all-installed-yum() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-33-rollBack-wazuh-installation-all-installed-yum-assert() {
    yum remove wazuh-manager -y
    
    rm -rf /var/ossec/

    yum remove filebeat -y 

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-34-rollBack-wazuh-installation-all-installed-zypper() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-34-rollBack-wazuh-installation-all-installed-zypper-assert() {
    zypper -n remove wazuh-manager
    rm -f /etc/init.d/wazuh-manager
    
    rm -rf /var/ossec/

    zypper -n remove filebeat

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-35-rollBack-wazuh-installation-all-installed-apt() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-35-rollBack-wazuh-installation-all-installed-apt-assert() {
    apt remove --purge wazuh-manager -y
    
    rm -rf /var/ossec/

    apt remove --purge filebeat -y

    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-36-rollBack-kibana-installation-all-installed-yum() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-36-rollBack-kibana-installation-all-installed-yum-assert() {
    yum remove opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-37-rollBack-kibana-installation-all-installed-zypper() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-37-rollBack-kibana-installation-all-installed-zypper-assert() {
    zypper -n remove opendistroforelasticsearch-kibana
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-38-rollBack-kibana-installation-all-installed-apt() {
    load-rollBack
    elasticsearchinstalled=1
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
    rollBack
}

test-38-rollBack-kibana-installation-all-installed-apt-assert() {
    apt remove --purge opendistroforelasticsearch-kibana -y
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-39-rollBack-aio-nothing-installed() {
    load-rollBack
    elasticsearchinstalled=
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
    rollBack
    @assert-success
}

test-40-rollBack-aio-all-remaining-files-yum() {
    load-rollBack
    elasticsearchinstalled=
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
    rollBack
}

test-40-rollBack-aio-all-remaining-files-yum-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-41-rollBack-aio-all-remaining-files-zypper() {
    load-rollBack
    elasticsearchinstalled=
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
    rollBack
}

test-41-rollBack-aio-all-remaining-files-zypper-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-42-rollBack-aio-all-remaining-files-apt() {
    load-rollBack
    elasticsearchinstalled=
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
    rollBack
}

test-42-rollBack-aio-all-remaining-files-apt-assert() {
    rm -rf /var/ossec/
    
    rm -rf /var/lib/elasticsearch/
    rm -rf /usr/share/elasticsearch/
    rm -rf /etc/elasticsearch/
    
    rm -rf /var/lib/filebeat/
    rm -rf /usr/share/filebeat/
    rm -rf /etc/filebeat/
    
    rm -rf /var/lib/kibana/
    rm -rf /usr/share/kibana/
    rm -rf /etc/kibana/

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-43-rollBack-nothing-installed-remove-yum-repo() {
    load-rollBack
    @mkdir -p /etc/yum.repos.d
    @touch /etc/yum.repos.d/wazuh.repo
    rollBack
    @rm /etc/yum.repos.d/wazuh.repo
}

test-43-rollBack-nothing-installed-remove-yum-repo-assert() {
    rm /etc/yum.repos.d/wazuh.repo

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-44-rollBack-nothing-installed-remove-zypper-repo() {
    load-rollBack
    @mkdir -p /etc/zypp/repos.d
    @touch /etc/zypp/repos.d/wazuh.repo
    rollBack
    @rm /etc/zypp/repos.d/wazuh.repo
}

test-44-rollBack-nothing-installed-remove-zypper-repo-assert() {
    rm /etc/zypp/repos.d/wazuh.repo

    rm -rf /var/log/elasticsearch/ /var/log/filebeat/ /etc/systemd/system/elasticsearch.service.wants/ /securityadmin_demo.sh  /etc/systemd/system/multi-user.target.wants/wazuh-manager.service  /etc/systemd/system/multi-user.target.wants/filebeat.service  /etc/systemd/system/multi-user.target.wants/elasticsearch.service  /etc/systemd/system/multi-user.target.wants/kibana.service  /etc/systemd/system/kibana.service /lib/firewalld/services/kibana.xml /lib/firewalld/services/elasticsearch.xml
}

test-45-rollBack-nothing-installed-remove-zypper-repo() {
    load-rollBack
    @mkdir -p /etc/apt/sources.list.d
    @touch /etc/apt/sources.list.d/wazuh.list
    rollBack
    @rm /etc/apt/sources.list.d/wazuh.list
}

test-45-rollBack-nothing-installed-remove-zypper-repo-assert() {
    rm /etc/apt/sources.list.d/wazuh.list
}

test-46-rollBack-nothing-installed-remove-/var/log/elasticsearch/() {
    load-rollBack
    @mkdir -p /var/log/elasticsearch/
    rollBack
    @rmdir /var/log/elasticsearch
}

test-46-rollBack-nothing-installed-remove-/var/log/elasticsearch/-assert() {
    rm -rf /var/log/elasticsearch/
}

test-47-rollBack-nothing-installed-remove-/var/log/filebeat/() {
    load-rollBack
    @mkdir -p /var/log/filebeat/
    rollBack
    @rmdir /var/log/filebeat/
}

test-47-rollBack-nothing-installed-remove-/var/log/filebeat/-assert() {
    rm -rf /var/log/filebeat/
}

test-48-rollBack-nothing-installed-remove-/securityadmin_demo.sh() {
    load-rollBack
    #@mocktrue -f /securityadmin_demo.sh
    @touch /securityadmin_demo.sh
    rollBack
    @rm /securityadmin_demo.sh
}

test-48-rollBack-nothing-installed-remove-/securityadmin_demo.sh-assert() {
    rm -f /securityadmin_demo.sh
}

test-49-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/wazuh-manager.service() {
    load-rollBack
    @mkdir -p /etc/systemd/system/multi-user.target.wants/
    @touch /etc/systemd/system/multi-user.target.wants/wazuh-manager.service
    rollBack
    @rm /etc/systemd/system/multi-user.target.wants/wazuh-manager.service
}

test-49-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/wazuh-manager.service-assert() {
    rm -f /etc/systemd/system/multi-user.target.wants/wazuh-manager.service
}

test-50-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/filebeat.service() {
    load-rollBack
    @mkdir -p /etc/systemd/system/multi-user.target.wants/
    @touch /etc/systemd/system/multi-user.target.wants/filebeat.service
    rollBack
    @rm /etc/systemd/system/multi-user.target.wants/filebeat.service
}

test-50-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/filebeat.service-assert() {
    rm -f /etc/systemd/system/multi-user.target.wants/filebeat.service
}

test-51-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/elasticsearch.service() {
    load-rollBack
    @mkdir -p /etc/systemd/system/multi-user.target.wants/
    @touch /etc/systemd/system/multi-user.target.wants/elasticsearch.service
    rollBack
    @rm /etc/systemd/system/multi-user.target.wants/elasticsearch.service
}

test-51-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/elasticsearch.service-assert() {
    rm -f /etc/systemd/system/multi-user.target.wants/elasticsearch.service
}

test-52-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/kibana.service() {
    load-rollBack
    @mkdir -p /etc/systemd/system/multi-user.target.wants/
    @touch /etc/systemd/system/multi-user.target.wants/kibana.service
    rollBack
    @rm /etc/systemd/system/multi-user.target.wants/kibana.service
}

test-52-rollBack-nothing-installed-remove-/etc/systemd/system/multi-user.target.wants/kibana.service-assert() {
    rm -f /etc/systemd/system/multi-user.target.wants/kibana.service
}

test-53-rollBack-nothing-installed-remove-/etc/systemd/system/kibana.service() {
    load-rollBack
    @mkdir -p /etc/systemd/system/
    @touch /etc/systemd/system/kibana.service
    rollBack
    @rm /etc/systemd/system/kibana.service
}

test-53-rollBack-nothing-installed-remove-/etc/systemd/system/kibana.service-assert() {
    rm -f /etc/systemd/system/kibana.service
}

test-54-rollBack-nothing-installed-remove-/lib/firewalld/services/kibana.xml() {
    load-rollBack
    @mkdir -p /lib/firewalld/services/
    @touch /lib/firewalld/services/kibana.xml
    rollBack
    @rm /lib/firewalld/services/kibana.xml
}

test-54-rollBack-nothing-installed-remove-/lib/firewalld/services/kibana.xml-assert() {
    rm -f /lib/firewalld/services/kibana.xml
}

test-55-rollBack-nothing-installed-remove-/lib/firewalld/services/elasticsearch.xml() {
    load-rollBack
    @mkdir -p /lib/firewalld/services/
    @touch /lib/firewalld/services/elasticsearch.xml
    rollBack
    @rm /lib/firewalld/services/elasticsearch.xml
}

test-55-rollBack-nothing-installed-remove-/lib/firewalld/services/elasticsearch.xml-assert() {
    rm -f /lib/firewalld/services/elasticsearch.xml
}

test-56-rollBack-nothing-installed-remove-/etc/systemd/system/elasticsearch.service.wants() {
    load-rollBack
    @mkdir -p /etc/systemd/system/elasticsearch.service.wants
    rollBack
    @rmdir /etc/systemd/system/elasticsearch.service.wants/
}

test-56-rollBack-nothing-installed-remove-/etc/systemd/system/elasticsearch.service.wants-assert() {
    rm -rf /etc/systemd/system/elasticsearch.service.wants
}

function load-createCertificates() {
    @load_function "${base_dir}/common.sh" createCertificates
}

test-57-createCertificates-aio() {
    load-createCertificates
    AIO=1
    base_path=/tmp
    createCertificates
}

test-57-createCertificates-aio-assert() {
    getConfig certificate/config_aio.yml /tmp/config.yml

    readConfig

    mkdir /tmp/certs

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

test-58-createCertificates-no-aio() {
    load-createCertificates
    base_path=/tmp
    createCertificates
}

test-58-createCertificates-no-aio-assert() {

    readConfig

    mkdir /tmp/certs

    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

function load-changePasswords() {
    @load_function "${base_dir}/common.sh" changePasswords
}

test-ASSERT-FAIL-59-changePasswords-no-tarfile() {
    load-changePasswords
    tar_file=
    changePasswords
}

test-60-changePasswords-with-tarfile() {
    load-changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-60-changePasswords-with-tarfile-assert() {
    checkInstalledPass
    readPasswordFileUsers
    changePassword
    rm -rf /tmp/password_file.yml
    @echo 
}

test-61-changePasswords-with-tarfile-aio() {
    load-changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    AIO=1
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-61-changePasswords-with-tarfile-aio-assert() {
    checkInstalledPass
    readUsers
    readPasswordFileUsers
    getNetworkHost
    createBackUp
    generateHash
    changePassword
    runSecurityAdmin
    rm -rf /tmp/password_file.yml
    @echo 1
}

test-62-changePasswords-with-tarfile-start-elastic-cluster() {
    load-changePasswords
    tar_file=tarfile.tar
    base_path=/tmp
    AIO=1
    @touch $tar_file
    @mock tar -xf tarfile.tar -C /tmp ./password_file.yml === @touch /tmp/password_file.yml
    changePasswords
    @echo $changeall
    @rm /tmp/password_file.yml
}

test-62-changePasswords-with-tarfile-start-elastic-cluster-assert() {
    checkInstalledPass
    readUsers
    readPasswordFileUsers
    getNetworkHost
    createBackUp
    generateHash
    changePassword
    runSecurityAdmin
    rm -rf /tmp/password_file.yml
    @echo 1
}

function load-getPass() {
    @load_function "${base_dir}/common.sh" getPass
}

test-63-getPass-no-args() {
    load-getPass
    users=(kibanaserver admin)
    passwords=(kibanaserver_pass admin_pass)
    getPass
    @echo $u_pass
}

test-63-getPass-no-args-assert() {
    @echo
}

test-64-getPass-admin() {
    load-getPass
    users=(kibanaserver admin)
    passwords=(kibanaserver_pass admin_pass)
    getPass admin
    @echo $u_pass
}

test-64-getPass-admin-assert() {
    @echo admin_pass
}

function load-startService() {
    @load_function "${base_dir}/common.sh" startService
}

test-ASSERT-FAIL-65-startService-no-args() {
    load-startService
    startService
}

test-ASSERT-FAIL-66-startService-no-service-manager() {
    load-startService
    @mockfalse ps -e
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @rm /etc/init.d/wazuh
    startService wazuh-manager
}

test-67-startService-systemd() {
    load-startService
    @mockfalse ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    startService wazuh-manager
}

test-67-startService-systemd-assert() {
    systemctl daemon-reload
    systemctl enable wazuh-manager.service
    systemctl start wazuh-manager.service
}

test-68-startService-systemd-error() {
    load-startService
    @mock ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @mockfalse systemctl start wazuh-manager.service
    startService wazuh-manager
}

test-68-startService-systemd-error-assert() {
    systemctl daemon-reload
    systemctl enable wazuh-manager.service
    rollBack
    exit 1
}

test-69-startService-initd() {
    load-startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-69-startService-initd-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    chkconfig wazuh-manager on
    service wazuh-manager start
    /etc/init.d/wazuh-manager start
    @rm /etc/init.d/wazuh-manager
}

test-70-startService-initd-error() {
    load-startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    #/etc/init.d/wazuh-manager is not executable -> It will fail
    startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-70-startService-initd-error-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    chkconfig wazuh-manager on
    service wazuh-manager start
    /etc/init.d/wazuh-manager start
    rollBack
    exit 1
    @rm /etc/init.d/wazuh-manager
}

test-71-startService-rc.d/init.d() {
    load-startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"

    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager

    startService wazuh-manager
    @rm /etc/rc.d/init.d/wazuh-manager
}

test-71-startService-rc.d/init.d-assert() {
    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager
    /etc/rc.d/init.d/wazuh-manager start
    @rm /etc/rc.d/init.d/wazuh-manager
}

function load-readPasswordFileUsers() {
    @load_function "${base_dir}/common.sh" readPasswordFileUsers
}

test-ASSERT-FAIL-72-readPasswordFileUsers-file-incorrect() {
    load-readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 0
    readPasswordFileUsers
}

test-73-readPasswordFileUsers-changeall-correct() {
    load-readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @echo wazuh kibanaserver
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @echo wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-73-readPasswordFileUsers-changeall-correct-assert() {
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-74-readPasswordFileUsers-changeall-user-doesnt-exist() {
    load-readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-74-readPasswordFileUsers-changeall-user-doesnt-exist-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-75-readPasswordFileUsers-no-changeall-kibana-correct() {
    load-readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword adminpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=
    kibanainstalled=1
    kibana=1
    readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-75-readPasswordFileUsers-no-changeall-kibana-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo kibanaserver admin
    @echo kibanaserverpassword adminpassword
}

test-76-readPasswordFileUsers-no-changeall-filebeat-correct() {
    load-readPasswordFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword adminpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=
    filebeatinstalled=1
    wazuh=1
    readPasswordFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-76-readPasswordFileUsers-no-changeall-filebeat-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo admin
    @echo adminpassword
}

