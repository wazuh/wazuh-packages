#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-passwords-readFileUsers() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-readFileUsers
}

test-ASSERT-FAIL-01-passwords-readFileUsers-file-incorrect() {
    load-passwords-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 0
    passwords-readFileUsers
}

test-02-passwords-readFileUsers-changeall-correct() {
    load-passwords-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @echo wazuh kibanaserver
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @echo wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    passwords-readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-02-passwords-readFileUsers-changeall-correct-assert() {
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-03-passwords-readFileUsers-changeall-user-doesnt-exist() {
    load-passwords-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    passwords-readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-03-passwords-readFileUsers-changeall-user-doesnt-exist-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-04-passwords-readFileUsers-no-changeall-correct() {
    load-passwords-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword adminpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=
    kibanainstalled=1
    kibana=1
    users=( kibanaserver admin )
    passwords-readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-04-passwords-readFileUsers-no-changeall-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo kibanaserver admin
    @echo kibanaserverpassword adminpassword
}

function load-passwords-changePassword() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-changePassword
}

test-05-passwords-changePassword-changeall-all-users-all-installed() {
    load-passwords-changePassword
    changeall=1
    indexerchinstalled=1
    filebeat_installed=1
    kibanainstalled=1
    users=( "kibanaserver" "admin" )
    passwords=( "kibanaserverpassword" "adminpassword" )
    hashes=( "11" "22")
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    passwords-changePassword
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
    @rm /etc/kibana/kibana.yml
}

test-05-passwords-changePassword-changeall-all-users-all-installed-assert() {
    awk -v new=11 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
    awk -v new=22 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
    echo "admin_configuration_string"
    recommon_startService "filebeat"
    echo "kibanaserver_configuration_string"
    recommon_startService "kibana"
}

test-06-passwords-changePassword-nuser-kibanaserver-kibana-installed() {
    load-passwords-changePassword
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    nuser="kibanaserver"
    password="kibanaserverpassword"
    hash="11"
    kibanainstalled=1
    indexerchinstalled=1
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    passwords-changePassword
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/kibana/kibana.yml
}

test-06-passwords-changePassword-nuser-kibanaserver-kibana-installed-assert() {
    awk -v new="11" 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
    echo "kibanaserver_configuration_string"
    recommon_startService "kibana"
}

test-07-passwords-changePassword-nuser-kibanaserver-kibana-not-installed() {
    load-passwords-changePassword
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    nuser="kibanaserver"
    password="kibanaserverpassword"
    hash="11"
    kibanainstalled=
    indexerchinstalled=1
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    passwords-changePassword
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/kibana/kibana.yml
}

test-07-passwords-changePassword-nuser-kibanaserver-kibana-not-installed-assert() {
    awk -v new="11" 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
}

test-08-passwords-changePassword-nuser-admin-filebeat-installed() {
    load-passwords-changePassword
    changeall=
    indexerchinstalled=1
    filebeat_installed=1
    nuser="admin"
    password="adminpassword"
    hash="11"
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    passwords-changePassword
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
}

test-08-passwords-changePassword-nuser-admin-filebeat-installed-assert() {
    awk -v new=11 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
    echo "admin_configuration_string"
    recommon_startService "filebeat"
}

test-09-passwords-changePassword-nuser-admin-filebeat-not-installed() {
    load-passwords-changePassword
    changeall=
    indexerchinstalled=1
    filebeat_installed=
    nuser="admin"
    password="adminpassword"
    hash="11"
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    passwords-changePassword
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
}

test-09-passwords-changePassword-nuser-admin-filebeat-not-installed-assert() {
    awk -v new=11 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/wazuh-indexer/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/wazuh-indexer/backup/internal_users.yml
}

test-10-passwords-changePassword-changeall-all-users-nothing-installed() {
    load-passwords-changePassword
    changeall=1
    indexerchinstalled=
    filebeat_installed=
    kibanainstalled=
    users=( "kibanaserver" "admin" )
    passwords=( "kibanaserverpassword" "adminpassword" )
    hashes=( "11" "22")
    @mkdir -p /usr/share/wazuh-indexer/backup/
    @touch /usr/share/wazuh-indexer/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    passwords-changePassword
    @assert-success
    @rm /usr/share/wazuh-indexer/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
    @rm /etc/kibana/kibana.yml
}

function load-passwords-checkInstalledPass() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-checkInstalledPass
}

test-11-passwords-checkInstalledPass-all-installed-yum() {
    load-passwords-checkInstalledPass
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh
    @mock grep -v kibana

    @mock grep filebeat === @echo filebeat.x86_64 7.10.2-1 @wazuh

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana.x86_64

    @mock grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml === @out "pem_path"

    adminpem=
    adminkey=

    passwords-checkInstalledPass

    @echo $indexerchinstalled
    @echo $filebeat_installed
    @echo $kibanainstalled
}

test-11-passwords-checkInstalledPass-all-installed-yum-assert() {

    passwords-readAdmincerts

    @echo "opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh"
    @echo "filebeat.x86_64 7.10.2-1 @wazuh"
    @echo "opendistroforelasticsearch-kibana.x86_64"
}

test-12-passwords-checkInstalledPass-all-installed-apt() {
    load-passwords-checkInstalledPass
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]
    @mock grep -v kibana

    @mock grep filebeat === @echo filebeat/now 7.10.2 amd64 [installed,local]

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]

    @mock grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml === @out "pem_path"

    adminpem=
    adminkey=

    passwords-checkInstalledPass

    @echo $indexerchinstalled
    @echo $filebeat_installed
    @echo $kibanainstalled

}

test-12-passwords-checkInstalledPass-all-installed-apt-assert() {

    passwords-readAdmincerts

    @echo "opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]"
    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo "opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]"
}

test-ASSERT-FAIL-13-passwords-checkInstalledPass-nothing-installed-apt() {
    load-passwords-checkInstalledPass
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    @mock grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml === @out "pem_path"

    passwords-checkInstalledPass
}

test-ASSERT-FAIL-14-passwords-checkInstalledPass-nothing-installed-yum() {
    load-passwords-checkInstalledPass
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    @mock grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml === @out "pem_path"

    passwords-checkInstalledPass
}

function load-passwords-checkUser() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-checkUser
}

test-ASSERT-FAIL-15-passwords-checkUser-no-nuser() {
    load-passwords-checkUser
    users=( "kibanaserver" "admin" )
    nuser=
    passwords-checkUser
}

test-ASSERT-FAIL-16-passwords-checkUser-incorrect-user() {
    load-passwords-checkUser
    users=( "kibanaserver" "admin" )
    nuser="wazuh"
    passwords-checkUser
}

test-17-passwords-checkUser-correct() {
    load-passwords-checkUser
    users=( "kibanaserver" "admin" )
    nuser="admin"
    passwords-checkUser
    @assert-success
}

function load-passwords-generatePasswordFile() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-generatePasswordFile
}

test-18-passwords-generatePasswordFile() {
    load-passwords-generatePasswordFile
    gen_file="/tmp/genfile.yml"
    passwords=("pass" "pass" "pass" "pass" "pass" "pass" "pass" "pass")
    passwords-generatePasswordFile
}

test-18-passwords-generatePasswordFile-assert() {
    passwords-generatePassword
    echo "User:"
    echo "  name: admin"
    echo "  password: pass"
    echo "User:"
    echo "  name: kibanaserver"
    echo "  password: pass"
    echo "User:"
    echo "  name: kibanaro"
    echo "  password: pass"
    echo "User:"
    echo "  name: logstash"
    echo "  password: pass"
    echo "User:"
    echo "  name: readall"
    echo "  password: pass"
    echo "User:"
    echo "  name: snapshotrestore"
    echo "  password: pass"
}

function load-passwords-getNetworkHost() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-getNetworkHost
}

test-19-passwords-getNetworkHost() {
    load-passwords-getNetworkHost
    @mock grep -hr "network.host:" /etc/wazuh-indexer/opensearch.yml === @out "network.host: 1.1.1.1"
    passwords-getNetworkHost
    @echo ${IP}
}

test-19-passwords-getNetworkHost-assert() {
    @echo 1.1.1.1
}

test-20-passwords-getNetworkHost-interface() {
    load-passwords-getNetworkHost
    @mock grep -hr "network.host:" /etc/wazuh-indexer/opensearch.yml === @out "network.host: _wlps01_"
    @mock ip -o -4 addr list wlps01 === @out "1.1.1.1"
    @mock awk '{print $4}' === @out ""
    @mock cut -d/ -f1 === @out ""
    passwords-getNetworkHost
    @echo ${IP}
}

test-20-passwords-getNetworkHost-interface-assert() {
    @echo 1.1.1.1
}

test-21-passwords-getNetworkHost-localhost() {
    load-passwords-getNetworkHost
    @mock grep -hr "network.host:" /etc/wazuh-indexer/opensearch.yml === @out "network.host: 0.0.0.0"
    passwords-getNetworkHost
    @echo ${IP}
}

test-21-passwords-getNetworkHost-localhost-assert() {
    @echo "localhost"
}

function load-passwords-readAdmincerts() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-readAdmincerts
}

test-ASSERT-FAIL-22-passwords-readAdmincerts-no-admin.pem() {
    load-passwords-readAdmincerts
    if [[ -f /etc/wazuh-indexer/certs/admin.pem ]]; then
        @rm -f /etc/wazuh-indexer/certs/admin.pem
    fi
    passwords-readAdmincerts
}

test-ASSERT-FAIL-23-passwords-readAdmincerts-no-admin_key.pem() {
    load-passwords-readAdmincerts
    @mkdir -p /etc/wazuh-indexer/certs
    if [[ ! -f /etc/wazuh-indexer/certs/admin.pem ]]; then
        @touch /etc/wazuh-indexer/certs/admin.pem
    fi
    if [[ -f /etc/wazuh-indexer/certs/admin-key.pem ]]; then
        @rm -f /etc/wazuh-indexer/certs/admin-key.pem
    fi

    if [[ -f /etc/wazuh-indexer/certs/admin.key ]]; then
        @rm -f /etc/wazuh-indexer/certs/admin.key
    fi
    passwords-readAdmincerts
    @rm /etc/wazuh-indexer/certs/admin.pem
    @rmdir /etc/wazuh-indexer/certs
}

test-24-passwords-readAdmincerts-all-correct-admin_key.pem() {
    load-passwords-readAdmincerts
    @mkdir -p /etc/wazuh-indexer/certs
    if [[ ! -f /etc/wazuh-indexer/certs/admin.pem ]]; then
        @touch /etc/wazuh-indexer/certs/admin.pem
    fi
    if [[ ! -f /etc/wazuh-indexer/certs/admin-key.pem ]]; then
        @touch /etc/wazuh-indexer/certs/admin-key.pem
    fi

    if [[ -f /etc/wazuh-indexer/certs/admin.key ]]; then
        @rm -f /etc/wazuh-indexer/certs/admin.key
    fi
    passwords-readAdmincerts
    @rm /etc/wazuh-indexer/certs/admin.pem
    @rm /etc/wazuh-indexer/certs/admin-key.pem
    @rmdir /etc/wazuh-indexer/certs
    @echo $adminpem
    @echo $adminkey
}

test-24-passwords-readAdmincerts-all-correct-admin_key.pem-assert() {
    @echo "/etc/wazuh-indexer/certs/admin.pem"
    @echo "/etc/wazuh-indexer/certs/admin-key.pem"
}

test-25-passwords-readAdmincerts-all-correct-admin.key() {
    load-passwords-readAdmincerts
    @mkdir -p /etc/wazuh-indexer/certs
    if [[ ! -f /etc/wazuh-indexer/certs/admin.pem ]]; then
        @touch /etc/wazuh-indexer/certs/admin.pem
    fi
    if [[ -f /etc/wazuh-indexer/certs/admin-key.pem ]]; then
        @rm -f /etc/wazuh-indexer/certs/admin-key.pem
    fi

    if [[ ! -f /etc/wazuh-indexer/certs/admin.key ]]; then
        @touch /etc/wazuh-indexer/certs/admin.key
    fi
    passwords-readAdmincerts
    @rm /etc/wazuh-indexer/certs/admin.pem
    @rm /etc/wazuh-indexer/certs/admin.key
    @rmdir /etc/wazuh-indexer/certs
    @echo $adminpem
    @echo $adminkey
}

test-25-passwords-readAdmincerts-all-correct-admin.key-assert() {
    @echo "/etc/wazuh-indexer/certs/admin.pem"
    @echo "/etc/wazuh-indexer/certs/admin.key"
}

function load-passwords-readUsers() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-readUsers
}

test-26-passwords-readUsers() {
    load-passwords-readUsers
    @mock grep -B 1 hash: /etc/wazuh-indexer/opensearch-security/internal_users.yml === @out
    @mock grep -v hash: === @out
    @mock grep -v "-" === @out
    @mock awk '{ print substr( $0, 1, length($0)-1 ) }' === @out "kibanaserver admin"
    passwords-readUsers
    @echo ${users[@]}
}

test-26-passwords-readUsers-assert() {
    @echo "kibanaserver admin"
}

function load-recommon_startService() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" recommon_startService
}

test-ASSERT-FAIL-27-recommon_startService-no-args() {
    load-recommon_startService
    recommon_startService
}

test-ASSERT-FAIL-28-recommon_startService-no-service-manager() {
    load-recommon_startService
    @mockfalse ps -e
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @rm /etc/init.d/wazuh
    recommon_startService wazuh-manager
}

test-29-recommon_startService-systemd() {
    load-recommon_startService
    @mockfalse ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    recommon_startService wazuh-manager
}

test-29-recommon_startService-systemd-assert() {
    systemctl daemon-reload
    systemctl restart wazuh-manager.service
}

test-30-recommon_startService-systemd-error() {
    load-recommon_startService
    @mock ps -e === @out 
    @mocktrue grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"
    @mockfalse systemctl restart wazuh-manager.service
    @mock type -t common_rollBack === @out "function"
    recommon_startService wazuh-manager
}

test-30-recommon_startService-systemd-error-assert() {
    systemctl daemon-reload
    common_rollBack
    exit 1
}

test-31-recommon_startService-initd() {
    load-recommon_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    recommon_startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-31-recommon_startService-initd-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    /etc/init.d/wazuh-manager restart
    @rm /etc/init.d/wazuh-manager
}

test-32-recommon_startService-initd-error() {
    load-recommon_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mocktrue grep -E -q "^\ *1\ .*init$"
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    #/etc/init.d/wazuh-manager is not executable -> It will fail
    @mock type -t common_rollBack === @out "function"
    recommon_startService wazuh-manager
    @rm /etc/init.d/wazuh-manager
}

test-32-recommon_startService-initd-error-assert() {
    @mkdir -p /etc/init.d
    @touch /etc/init.d/wazuh-manager
    @chmod +x /etc/init.d/wazuh-manager
    /etc/init.d/wazuh-manager restart
    common_rollBack
    exit 1
    @rm /etc/init.d/wazuh-manager
}

test-33-recommon_startService-rc.d/init.d() {
    load-recommon_startService
    @mock ps -e === @out 
    @mockfalse grep -E -q "^\ *1\ .*systemd$"
    @mockfalse grep -E -q "^\ *1\ .*init$"

    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager

    recommon_startService wazuh-manager
    @rm /etc/rc.d/init.d/wazuh-manager
}

test-33-recommon_startService-rc.d/init.d-assert() {
    @mkdir -p /etc/rc.d/init.d
    @touch /etc/rc.d/init.d/wazuh-manager
    @chmod +x /etc/rc.d/init.d/wazuh-manager
    /etc/rc.d/init.d/wazuh-manager start
    @rm /etc/rc.d/init.d/wazuh-manager
}

function load-passwords-generateHash() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" passwords-generateHash
}

test-34-passwords-generateHash-changeall() {
    load-passwords-generateHash
    passwords=("kibanaserverpassword" "adminpassword")
    changeall=1
    @mock grep -v WARNING === @out ""
    @mock bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "kibanaserverpassword" === @out "11111111"
    @mock bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "adminpassword" === @out "22222222"
    passwords-generateHash
    @echo ${hashes[@]}
}

test-34-passwords-generateHash-changeall-assert() {
    @echo "11111111 22222222"
}

test-ASSERT-FAIL-35-passwords-generateHash-changeall-error() {
    load-passwords-generateHash
    passwords=("kibanaserverpassword" "adminpassword")
    changeall=1
    @mockfalse grep -v WARNING
    @mock bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "kibanaserverpassword" === @out "11111111"
    @mockfalse bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "adminpassword"
    passwords-generateHash
    @echo ${hashes[@]}
}

test-36-passwords-generateHash-nuser() {
    load-passwords-generateHash
    nuser="kibanaserver"
    password="kibanaserverpassword"
    changeall=
    @mock grep -v WARNING === @out ""
    @mock bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "kibanaserverpassword" === @out "11111111"
    passwords-generateHash
    @echo ${hash}
}

test-36-passwords-generateHash-nuser-assert() {
    @echo "11111111"
}

test-ASSERT-FAIL-37-passwords-generateHash-nuser-error() {
    load-passwords-generateHash
    nuser="kibanaserver"
    password="kibanaserverpassword"
    changeall=
    @mockfalse grep -v WARNING
    @mockfalse bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "kibanaserverpassword"
    passwords-generateHash
}