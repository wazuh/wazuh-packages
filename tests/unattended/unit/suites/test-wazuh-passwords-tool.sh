#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger_pass
}

function load-readFileUsers() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" readFileUsers
}

test-ASSERT-FAIL-01-readFileUsers-file-incorrect() {
    load-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 0
    readFileUsers
}

test-02-readFileUsers-changeall-correct() {
    load-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @echo wazuh kibanaserver
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @echo wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-02-readFileUsers-changeall-correct-assert() {
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-03-readFileUsers-changeall-user-doesnt-exist() {
    load-readFileUsers
    p_file=/tmp/passfile.yml
    @mock grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*[A-Za-z0-9_\-]+\s*)+\Z' /tmp/passfile.yml === @echo 1
    @mock grep name: /tmp/passfile.yml === @out wazuh kibanaserver admin
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    @mock grep password: /tmp/passfile.yml === @out wazuhpassword kibanaserverpassword
    @mock awk '{ print substr( $2, 1, length($2) ) }'
    changeall=1
    users=( wazuh kibanaserver )
    readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-03-readFileUsers-changeall-user-doesnt-exist-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword
    @echo wazuh kibanaserver
    @echo wazuhpassword kibanaserverpassword
}

test-04-readFileUsers-no-changeall-correct() {
    load-readFileUsers
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
    readFileUsers
    @echo ${fileusers[*]}
    @echo ${filepasswords[*]}
    @echo ${users[*]}
    @echo ${passwords[*]}
}

test-04-readFileUsers-no-changeall-correct-assert() {
    @echo wazuh kibanaserver admin
    @echo wazuhpassword kibanaserverpassword adminpassword
    @echo kibanaserver admin
    @echo kibanaserverpassword adminpassword
}

function load-changePassword() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" changePassword
}

test-05-changePassword-changeall-all-users-all-installed() {
    load-changePassword
    changeall=1
    elasticsearchinstalled=1
    filebeatinstalled=1
    kibanainstalled=1
    users=( "kibanaserver" "admin" )
    passwords=( "kibanaserverpassword" "adminpassword" )
    hashes=( "11" "22")
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    changePassword
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
    @rm /etc/kibana/kibana.yml
}

test-05-changePassword-changeall-all-users-all-installed-assert() {
    awk -v new=11 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
    awk -v new=22 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
    echo "admin_configuration_string"
    restartService "filebeat"
    echo "kibanaserver_configuration_string"
    restartService "kibana"
}

test-06-changePassword-nuser-kibanaserver-kibana-installed() {
    load-changePassword
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    nuser="kibanaserver"
    password="kibanaserverpassword"
    hash="11"
    kibanainstalled=1
    elasticsearchinstalled=1
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    changePassword
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/kibana/kibana.yml
}

test-06-changePassword-nuser-kibanaserver-kibana-installed-assert() {
    awk -v new="11" 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
    echo "kibanaserver_configuration_string"
    restartService "kibana"
}

test-07-changePassword-nuser-kibanaserver-kibana-not-installed() {
    load-changePassword
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    nuser="kibanaserver"
    password="kibanaserverpassword"
    hash="11"
    kibanainstalled=
    elasticsearchinstalled=1
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    changePassword
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/kibana/kibana.yml
}

test-07-changePassword-nuser-kibanaserver-kibana-not-installed-assert() {
    awk -v new="11" 'prev=="kibanaserver:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
}

test-08-changePassword-nuser-admin-filebeat-installed() {
    load-changePassword
    changeall=
    elasticsearchinstalled=1
    filebeatinstalled=1
    nuser="admin"
    password="adminpassword"
    hash="11"
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    changePassword
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
}

test-08-changePassword-nuser-admin-filebeat-installed-assert() {
    awk -v new=11 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
    echo "admin_configuration_string"
    restartService "filebeat"
}

test-09-changePassword-nuser-admin-filebeat-not-installed() {
    load-changePassword
    changeall=
    elasticsearchinstalled=1
    filebeatinstalled=
    nuser="admin"
    password="adminpassword"
    hash="11"
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    changePassword
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
}

test-09-changePassword-nuser-admin-filebeat-not-installed-assert() {
    awk -v new=11 'prev=="admin:"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml
    mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml
}

test-10-changePassword-changeall-all-users-nothing-installed() {
    load-changePassword
    changeall=1
    elasticsearchinstalled=
    filebeatinstalled=
    kibanainstalled=
    users=( "kibanaserver" "admin" )
    passwords=( "kibanaserverpassword" "adminpassword" )
    hashes=( "11" "22")
    @mkdir -p /usr/share/elasticsearch/backup/
    @touch /usr/share/elasticsearch/backup/internal_users.yml
    @mkdir -p /etc/filebeat
    @touch /etc/filebeat/filebeat.yml
    @mkdir -p /etc/kibana
    @touch /etc/kibana/kibana.yml
    @mock grep "password:" /etc/filebeat/filebeat.yml === @out "wazuhpasswordold"
    @mock awk '{sub("password: .*", "password: adminpassword")}1' /etc/filebeat/filebeat.yml === @out "admin_configuration_string"
    @mock grep "password:" /etc/kibana/kibana.yml === @out "kibanapasswordold"
    @mock awk '{sub("elasticsearch.password: .*", "elasticsearch.password: kibanaserverpassword")}1' /etc/kibana/kibana.yml === @out "kibanaserver_configuration_string"
    changePassword
    @assert-success
    @rm /usr/share/elasticsearch/backup/internal_users.yml
    @rm /etc/filebeat/filebeat.yml
    @rm /etc/kibana/kibana.yml
}

function load-checkInstalledPass() {
    @load_function "${base_dir}/wazuh-passwords-tool.sh" checkInstalledPass
}

test-11-checkInstalledPass-all-installed-yum() {
    load-checkInstalledPass
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh
    @mock grep -v kibana

    @mock grep filebeat === @echo filebeat.x86_64 7.10.2-1 @wazuh

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana.x86_64

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    adminpem=
    adminkey=

    checkInstalledPass

    @echo $elasticsearchinstalled
    @echo $filebeatinstalled
    @echo $kibanainstalled
}

test-11-checkInstalledPass-all-installed-yum-assert() {

    readAdmincerts

    @echo "opendistroforelasticsearch.x86_64 1.13.2-1 @wazuh"
    @echo "filebeat.x86_64 7.10.2-1 @wazuh"
    @echo "opendistroforelasticsearch-kibana.x86_64"
}

test-12-checkInstalledPass-all-installed-zypper() {
    load-checkInstalledPass
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep opendistroforelasticsearch === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @mock grep -v kibana

    @mock grep filebeat === @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"

    @mock grep opendistroforelasticsearch-kibana === @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    adminpem=
    adminkey=

    checkInstalledPass

    @echo $elasticsearchinstalled
    @echo $filebeatinstalled
    @echo $kibanainstalled

}

test-12-checkInstalledPass-all-installed-zypper-assert() {

    readAdmincerts

    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch | 1.13.2-1 | x86_64"
    @echo "i+ | EL-20211102 - Wazuh | filebeat | 7.10.2-1 | x86_64"
    @echo "i+ | EL-20211102 - Wazuh | opendistroforelasticsearch-kibana | 1.13.2-1 | x86_64"
}

test-13-checkInstalledPass-all-installed-apt() {
    load-checkInstalledPass
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep opendistroforelasticsearch === @echo opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]
    @mock grep -v kibana

    @mock grep filebeat === @echo filebeat/now 7.10.2 amd64 [installed,local]

    @mock grep opendistroforelasticsearch-kibana === @echo opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    adminpem=
    adminkey=

    checkInstalledPass

    @echo $elasticsearchinstalled
    @echo $filebeatinstalled
    @echo $kibanainstalled

}

test-13-checkInstalledPass-all-installed-apt-assert() {

    readAdmincerts

    @echo "opendistroforelasticsearch/stable,now 1.13.2-1 amd64 [installed]"
    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo "opendistroforelasticsearch-kibana/now 1.13.2 amd64 [installed,local]"
}

test-ASSERT-FAIL-14-checkInstalledPass-nothing-installed-apt() {
    load-checkInstalledPass
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    checkInstalledPass
}

test-ASSERT-FAIL-15-checkInstalledPass-nothing-installed-yum() {
    load-checkInstalledPass
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    checkInstalledPass
}

test-ASSERT-FAIL-16-checkInstalledPass-nothing-installed-zypper() {
    load-checkInstalledPass
    sys_type="zypper"

    @mocktrue zypper packages
    @mock grep i+

    @mock grep wazuh-manager

    @mock grep opendistroforelasticsearch
    @mock grep -v kibana

    @mock grep filebeat

    @mock grep opendistroforelasticsearch-kibana

    @mock grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml === @out "pem_path"

    checkInstalledPass
}