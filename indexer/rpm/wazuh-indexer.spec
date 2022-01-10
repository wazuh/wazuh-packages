Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-indexer
Version:     4.3.0
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
AutoReqProv: no
Requires: coreutils initscripts
ExclusiveOS: linux
BuildRequires: tar shadow-utils

# -----------------------------------------------------------------------------

%global USER %{name}
%global GROUP %{name}
%global CONFIG_DIR /etc/%{name}
%global LOG_DIR /var/log/%{name}
%global LIB_DIR /var/lib/%{name}
%global PID_DIR /var/run/%{name}
%global SYS_DIR /usr/lib
%global INSTALL_DIR /usr/share/%{name}

# -----------------------------------------------------------------------------

%description
Wazuh indexer package

# -----------------------------------------------------------------------------

%prep
# Clean BUILDROOT
rm -fr %{buildroot}

# Create package group
getent group %{GROUP} || groupadd -r %{GROUP}

# Create package user
if ! id %{USER} &> /dev/null; then
    useradd --system \
            --no-create-home \
            --home-dir %{INSTALL_DIR} \
            --gid %{GROUP} \
            --shell /sbin/nologin \
            --comment "%{USER} user" \
            %{USER}
fi

# -----------------------------------------------------------------------------

%install
# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{INSTALL_DIR}
mkdir -p ${RPM_BUILD_ROOT}/etc
mkdir -p ${RPM_BUILD_ROOT}%{LOG_DIR}
mkdir -p ${RPM_BUILD_ROOT}%{LIB_DIR}
mkdir -p ${RPM_BUILD_ROOT}%{PID_DIR}
mkdir -p ${RPM_BUILD_ROOT}%{SYS_DIR}

# Download required sources
curl -kOL https://s3.amazonaws.com/warehouse.wazuh.com/indexer/wazuh-indexer-base-linux-x64.tar.gz
tar xzvf wazuh-indexer-*.tar.gz && rm -f wazuh-indexer-*.tar.gz
chown -R %{USER}:%{GROUP} wazuh-indexer-*/*

# Copy the installed files into RPM_BUILD_ROOT directory
mv wazuh-indexer-*/etc ${RPM_BUILD_ROOT}/
mv wazuh-indexer-*%{SYS_DIR}/* ${RPM_BUILD_ROOT}%{SYS_DIR}/
rm -rf wazuh-indexer-*/etc
rm -rf wazuh-indexer-*/usr
cp -pr wazuh-indexer-*/* ${RPM_BUILD_ROOT}%{INSTALL_DIR}/
mv ${RPM_BUILD_ROOT}/usr/lib/systemd/system/wazuh-indexer_centos.service ${RPM_BUILD_ROOT}/usr/lib/systemd/system/wazuh-indexer.service
rm -rf ${RPM_BUILD_ROOT}/usr/lib/systemd/system/wazuh-indexer_debian.service

# -----------------------------------------------------------------------------

%pre
# Create package group
getent group %{GROUP} > /dev/null 2>&1 || groupadd -r %{GROUP}

if ! id %{USER} &> /dev/null; then
    useradd --system \
            --no-create-home \
            --home-dir %{INSTALL_DIR} \
            --gid %{GROUP} \
            --shell /sbin/nologin \
            --comment "%{USER} user" \
            %{USER} > /dev/null 2>&1 
fi

# -----------------------------------------------------------------------------

%post
sysctl -w vm.max_map_count=262144 > /dev/null 2>&1 
ulimit -Hn 65535 > /dev/null 2>&1 
sudo -u %{USER} CLK_TK=`/usr/bin/getconf CLK_TCK` OPENSEARCH_PATH_CONF=%{CONFIG_DIR} %{INSTALL_DIR}/bin/opensearch --quiet > /dev/null 2>&1 &

sleep 15

sudo -u %{USER} OPENSEARCH_PATH_CONF=%{CONFIG_DIR} JAVA_HOME=%{INSTALL_DIR}/jdk %{INSTALL_DIR}/plugins/opensearch-security/tools/securityadmin.sh -cd %{INSTALL_DIR}/plugins/opensearch-security/securityconfig -icl -p 9800 -cd %{INSTALL_DIR}/plugins/opensearch-security/securityconfig -nhnv -cacert %{CONFIG_DIR}/certs/root-ca.pem -cert %{CONFIG_DIR}/certs/admin.pem -key %{CONFIG_DIR}/certs/admin-key.pem >> %{LOG_DIR}/securityadmin.log

sleep 5

kill -15 `pgrep -f opensearch` > /dev/null 2>&1

sleep 10

rm -rf %{LOG_DIR}/* > /dev/null 2>&1

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%defattr(-, %{USER}, %{GROUP})
%dir %attr(750, %{USER}, %{GROUP}) %{CONFIG_DIR}
%dir %attr(750, %{USER}, %{GROUP}) %{LIB_DIR}
%dir %attr(750, %{USER}, %{GROUP}) %{LOG_DIR}

%config(noreplace) %attr(0660, root, %{GROUP}) "/etc/sysconfig/%{name}"
%attr(0750, root, root) /etc/init.d/%{name}
%attr(0640, root, root) %{SYS_DIR}/sysctl.d/%{name}.conf
%attr(0640, root, root) %{SYS_DIR}/systemd/system/%{name}.service
%attr(0640, root, root) %{SYS_DIR}/systemd/system/%{name}-performance-analyzer.service
%attr(0640, root, root) %{SYS_DIR}/tmpfiles.d/%{name}.conf

%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/bin
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/bin/performance-analyzer-rca
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/performance-analyzer-rca-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/sqlite-jdbc-3.32.3.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-stub-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/log4j-api-2.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/bcpkix-jdk15on-1.68.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/bcprov-jdk15on-1.68.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/jackson-databind-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/protobuf-java-3.11.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/gson-2.8.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/commons-lang3-3.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/log4j-core-2.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/perfmark-api-0.19.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/guava-28.2-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-core-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-netty-shaded-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-context-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/annotations-4.1.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/animal-sniffer-annotations-1.18.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/jackson-annotations-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/proto-google-common-protos-1.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/javax.annotation-api-1.3.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/checker-qual-2.10.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/commons-io-2.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/jooq-3.10.8.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/jackson-core-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-protobuf-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-protobuf-lite-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/grpc-api-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/lib/failureaccess-1.0.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_bin
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_bin/performance-analyzer-agent
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/agent-stats-metadata
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/plugin-stats-metadata
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/performance-analyzer.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/rca_master.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/rca.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/opensearch_security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/log4j2.xml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/rca_idle_master.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/performance-analyzer-rca/pa_config/supervisord.conf
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-shard
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-node
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-keystore
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-plugin
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-cli
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-env
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/performance-analyzer-agent-cli
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-env-from-file
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/opensearch-upgrade
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/bin/systemd-entrypoint
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/hppc-0.8.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-highlighter-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-geo-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-spatial-extras-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-cli-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/java-version-checker-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-memory-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/log4j-api-2.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-analyzers-common-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/snakeyaml-1.26.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/joda-time-2.10.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-x-content-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-join-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-plugin-classloader-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jna-5.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jackson-dataformat-smile-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/log4j-core-2.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-suggest-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-launchers-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jackson-dataformat-yaml-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/HdrHistogram-2.1.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-core-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-queries-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-secure-sm-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/plugin-cli
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/plugin-cli/bcpg-fips-1.0.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/plugin-cli/opensearch-plugin-cli-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/plugin-cli/bc-fips-1.0.2.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/upgrade-cli
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/upgrade-cli/jackson-annotations-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/upgrade-cli/jackson-databind-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/upgrade-cli/jackson-core-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/upgrade-cli/opensearch-upgrade-cli-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/keystore-cli
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/tools/keystore-cli/keystore-cli-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-queryparser-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-sandbox-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jts-core-1.15.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jackson-dataformat-cbor-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-grouping-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-misc-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jackson-core-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/t-digest-3.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/opensearch-core-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-backward-codecs-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/spatial4j-0.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/jopt-simple-5.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/lib/lucene-spatial3d-8.10.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs
%config(noreplace) %attr(400, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs/admin.pem
%config(noreplace) %attr(400, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs/admin-key.pem
%config(noreplace) %attr(400, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs/demo-indexer.pem
%config(noreplace) %attr(400, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs/demo-indexer-key.pem
%config(noreplace) %attr(400, %{USER}, %{GROUP}) %{CONFIG_DIR}/certs/root-ca.pem
%dir %attr(750, %{USER}, %{GROUP}) %{CONFIG_DIR}/opensearch-observability
%attr(660, %{USER}, %{GROUP}) %{CONFIG_DIR}/opensearch-observability/observability.yml
%dir %attr(750, %{USER}, %{GROUP}) %{CONFIG_DIR}/opensearch-reports-scheduler
%attr(660, %{USER}, %{GROUP}) %{CONFIG_DIR}/opensearch-reports-scheduler/reports-scheduler.yml
%config(noreplace) %attr(660, %{USER}, %{GROUP}) %{CONFIG_DIR}/jvm.options
%config(noreplace) %attr(660, %{USER}, %{GROUP}) %{CONFIG_DIR}/opensearch.yml
%dir %attr(750, %{USER}, %{GROUP}) %{CONFIG_DIR}/jvm.options.d
%config(noreplace) %attr(660, %{USER}, %{GROUP}) %{CONFIG_DIR}/log4j2.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/NOTICE.txt
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/LICENSE.txt
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/opensearch-observability-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/kotlin-stdlib-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/annotations-13.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/kotlin-stdlib-common-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-observability/guava-15.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/jsoup-1.14.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/minimal-json-0.9.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/json-flattener-0.1.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/kotlin-stdlib-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/annotations-13.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/json-20180813.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/kotlin-stdlib-common-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/opensearch-reports-scheduler-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-reports-scheduler/guava-15.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-beans-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/resilience4j-core-1.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/core-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-expression-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-aop-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/guava-29.0-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/protocol-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-context-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/slf4j-api-1.7.30.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/druid-1.0.15.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/sql-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/opensearch-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/commons-lang3-3.10.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/jackson-databind-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/checker-qual-2.11.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/reindex-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/gson-2.8.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-core-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/antlr4-runtime-4.7.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/json-20180813.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/NOTICE.txt
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/resilience4j-retry-1.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/spring-jcl-5.2.5.RELEASE.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/LICENSE.txt
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/jackson-annotations-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/vavr-match-0.10.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/parent-join-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/vavr-0.10.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/presto-matching-0.240.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/legacy-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/opensearch-ssl-config-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/commons-codec-1.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/opensearch-sql-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/commons-math3-3.6.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/ppl-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/httpcore-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/failureaccess-1.0.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-sql/common-1.2.3.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/ipaddress-5.3.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/annotations-13.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/kotlinx-coroutines-core-1.3.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/opensearch-cross-cluster-replication-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-common-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-jdk7-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-jdk8-1.3.72.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/commons-lang-2.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/guava-29.0-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/opensearch-knn-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/checker-qual-2.11.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/plugin-descriptor.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/knnlib
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/knnlib/libopensearchknn_common.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/knnlib/libgomp.so.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/knnlib/libopensearchknn_nmslib.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/knnlib/libopensearchknn_faiss.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-knn/failureaccess-1.0.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/ipaddress-5.3.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/kotlin-stdlib-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/annotations-13.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/notification-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/kotlin-stdlib-jdk8-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/opensearch-index-management-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/kotlin-stdlib-common-1.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-index-management/kotlin-stdlib-jdk7-1.4.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/sqlite-jdbc-3.32.3.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-stub-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/bcpkix-jdk15on-1.68.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/bcprov-jdk15on-1.68.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/jackson-databind-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/protobuf-java-3.11.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/paranamer-2.8.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/jackson-module-paranamer-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/gson-2.8.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/commons-lang3-3.9.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/perfmark-api-0.19.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/opensearch-performance-analyzer-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/guava-28.2-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-core-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-netty-shaded-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-context-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/annotations-4.1.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/animal-sniffer-annotations-1.18.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/jackson-annotations-2.11.4.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_bin
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_bin/performance-analyzer-agent
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/performance-analyzer.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/rca_master.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/rca.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/agent-stats-metadata
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/plugin-stats-metadata
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/opensearch_security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/log4j2.xml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/rca_idle_master.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/pa_config/supervisord.conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/performanceanalyzer-rca-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/proto-google-common-protos-1.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/javax.annotation-api-1.3.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/checker-qual-2.10.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/commons-io-2.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/jooq-3.10.8.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-protobuf-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-protobuf-lite-1.28.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/extensions
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/extensions/performance-analyzer-agent
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/grpc-api-1.28.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-performance-analyzer/failureaccess-1.0.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-job-scheduler
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-job-scheduler/opensearch-job-scheduler-spi-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-job-scheduler/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-job-scheduler/opensearch-job-scheduler-1.2.3.0.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-saml-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-codec-1.14.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/java-saml-2.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/slf4j-api-1.7.25.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/minimal-json-0.9.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-security-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.jws-api-2.1.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-codec-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jackson-databind-2.11.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.activation-1.2.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-logging-1.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/json-path-2.4.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/aggs-matrix-stats-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/lang-mustache-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/bcprov-jdk15on-1.67.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/json-flattener-0.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/cxf-rt-rs-json-basic-3.4.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/snappy-java-1.1.7.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-common-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-xmlsec-impl-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/txw2-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/cxf-core-3.4.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jackson-annotations-2.11.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/metrics-core-3.1.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jboss-rmi-api_1.0_spec-1.0.6.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-soap-impl-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/j2objc-annotations-1.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-messaging-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-storage-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-lang-2.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/mapper-extras-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.xml.bind-api-2.3.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-saml-impl-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/java-saml-core-2.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/cryptacular-1.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-core-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-cli-1.3.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jjwt-api-0.10.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/log4j-slf4j-impl-2.17.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-lang3-3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/lz4-java-1.7.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/rank-eval-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/ldaptive-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.xml.soap-api-1.4.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensearch-security-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jjwt-jackson-0.10.5.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/whitelist.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/tenants.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/nodes_dn.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/audit.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/action_groups.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/config.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/roles_mapping.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/roles.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/opensearch.yml.example
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/securityconfig/internal_users.yml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/woodstox-core-6.2.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/eventbus-3.2.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/istack-commons-runtime-3.0.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/asm-9.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/parent-join-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jjwt-impl-0.10.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/json-smart-2.4.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/xmlsec-2.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/tools
%attr(740, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/tools/hash.sh
%attr(740, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/tools/securityadmin.sh
%attr(740, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/tools/audit_config_migrater.sh
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.xml.ws-api-2.3.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/xmlschema-core-2.2.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/httpclient-cache-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/velocity-1.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/error_prone_annotations-2.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-resolver-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/transport-netty4-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/animal-sniffer-annotations-1.14.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/stax-ex-1.8.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/compiler-0.9.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/guava-25.1-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-xmlsec-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/zjsonpatch-0.4.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/accessors-smart-2.4.7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensearch-rest-high-level-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/cxf-rt-security-3.4.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/java-support-7.5.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-transport-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/kafka-clients-2.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/stax2-api-4.2.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/cxf-rt-rs-security-jose-3.4.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-profile-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jaxb-runtime-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-security-impl-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-collections-3.2.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-buffer-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/saaj-impl-1.5.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/commons-text-1.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/zstd-jni-1.4.4-7.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/jakarta.annotation-api-1.3.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/geronimo-jta_1.1_spec-1.1.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/checker-qual-2.0.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-codec-http-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/httpcore-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/opensaml-soap-api-3.4.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-security/netty-handler-4.1.69.Final.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-asynchronous-search
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-asynchronous-search/opensearch-asynchronous-search-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-asynchronous-search/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-asynchronous-search/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-asynchronous-search/plugin-security.policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/commons-lang-2.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/org.jacoco.report-0.8.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/slf4j-api-1.7.25.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/guava-29.0-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/randomcutforest-core-2.0.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/randomcutforest-serialization-2.0.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/jackson-databind-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/checker-qual-2.11.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/randomcutforest-parkservices-2.0.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/gson-2.8.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/protostuff-collectionschema-1.7.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/opensearch-anomaly-detection-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/org.jacoco.ant-0.8.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/commons-pool2-2.10.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/sketches-core-0.13.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/org.jacoco.core-0.8.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/org.jacoco.agent-0.8.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/protostuff-api-1.7.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/memory-0.12.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/jackson-annotations-2.11.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/protostuff-runtime-1.7.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/protostuff-core-1.7.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/commons-logging-1.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/commons-codec-1.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/commons-math3-3.6.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/httpcore-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-anomaly-detection/failureaccess-1.0.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/error_prone_annotations-2.3.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/cron-utils-9.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/javax.mail-1.6.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/slf4j-api-1.7.30.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/ipaddress-5.3.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/j2objc-annotations-1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/commons-lang3-3.11.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/common-utils-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/jsr305-3.0.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/javax.el-3.0.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlinx-coroutines-core-1.1.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/annotations-13.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/guava-30.0-jre.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/activation-1.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/alerting-core-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/google-java-format-1.10.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/alerting-notification-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlin-stdlib-common-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/commons-logging-1.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlin-stdlib-jdk7-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/checker-qual-3.5.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/opensearch-alerting-1.2.3.0.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlinx-coroutines-core-common-1.1.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlin-stdlib-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/commons-codec-1.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/kotlin-stdlib-jdk8-1.3.72.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/httpcore-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/plugins/opensearch-alerting/failureaccess-1.0.1.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/jcodings-1.0.44.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/joni-2.1.29.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/opensearch-grok-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/opensearch-dissect-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-common/ingest-common-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/geo
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/geo/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/geo/geo-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/GeoLite2-Country.mmdb
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/GeoLite2-City.mmdb
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/geoip2-2.13.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/maxmind-db-1.3.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/jackson-annotations-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/jackson-databind-2.12.5.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/ingest-geoip-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/GeoLite2-ASN.mmdb
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-geoip/plugin-security.policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/percolator
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/percolator/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/percolator/percolator-client-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/analysis-common
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/analysis-common/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/analysis-common/analysis-common-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/aggs-matrix-stats
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/aggs-matrix-stats/aggs-matrix-stats-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/aggs-matrix-stats/plugin-descriptor.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/repository-url
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/repository-url/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/repository-url/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/repository-url/repository-url-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-mustache
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-mustache/lang-mustache-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-mustache/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-mustache/compiler-0.9.6.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-mustache/plugin-security.policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/systemd
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/systemd/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/systemd/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/systemd/systemd-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-codec-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-common-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-resolver-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/transport-netty4-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-transport-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-buffer-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-codec-http-4.1.69.Final.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/transport-netty4/netty-handler-4.1.69.Final.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/lucene-expressions-8.10.1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/lang-expression-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/antlr4-runtime-4.5.1-1.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/asm-5.0.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/asm-commons-5.0.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-expression/asm-tree-5.0.4.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/asm-7.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/antlr4-runtime-4.5.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/asm-tree-7.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/asm-util-7.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/asm-analysis-7.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/asm-commons-7.2.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/lang-painless-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/lang-painless/opensearch-scripting-painless-spi-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/rank-eval
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/rank-eval/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/rank-eval/rank-eval-client-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/reindex-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/commons-logging-1.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/opensearch-dashboards-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/opensearch-ssl-config-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/commons-codec-1.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/opensearch-dashboards/httpcore-4.4.12.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-user-agent
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-user-agent/ingest-user-agent-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/ingest-user-agent/plugin-descriptor.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/mapper-extras
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/mapper-extras/mapper-extras-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/mapper-extras/plugin-descriptor.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/parent-join
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/parent-join/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/parent-join/parent-join-client-1.2.3.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/httpcore-nio-4.4.12.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/httpasyncclient-4.1.4.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/reindex-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/plugin-descriptor.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/commons-logging-1.1.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/opensearch-rest-client-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/plugin-security.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/httpclient-4.5.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/opensearch-ssl-config-1.2.3.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/commons-codec-1.13.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/modules/reindex/httpcore-4.4.12.jar
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jrunscript.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jcmd.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/java.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jdeprscan.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/javadoc.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/rmid.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jar.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jdb.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jpackage.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jstatd.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/serialver.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/keytool.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jconsole.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jlink.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jhsdb.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jaotc.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jshell.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/rmiregistry.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/javac.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jstack.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jfr.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jps.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jarsigner.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jmod.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jstat.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jinfo.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jmap.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/jdeps.1
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/man/man1/javap.1
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jdeps
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/rmiregistry
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jrunscript
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jdeprscan
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jar
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jmap
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jps
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jstatd
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/rmid
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/java
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jdb
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jimage
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/javadoc
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jconsole
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jcmd
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jstack
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jinfo
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jpackage
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/serialver
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/javap
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/keytool
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jaotc
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jarsigner
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jhsdb
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jlink
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jfr
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jstat
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/javac
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jmod
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/bin/jshell
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/release
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/LICENSE
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/ADDITIONAL_LICENSE_INFO
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/icu.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/c-libutl.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/public_suffix.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/cldr.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/aes.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/ASSEMBLY_EXCEPTION
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/asm.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.base/unicode.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.security.sasl
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.scripting
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.dynalink/dynalink.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.management
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.javadoc/jqueryUI.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.javadoc/jquery.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml/xalan.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml/xerces.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml/jcup.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml/bcel.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml/dom.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.smartcardio
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.smartcardio/pcsclite.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.transaction.xa
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.prefs
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.compiler
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.logging
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.internal.opt/jopt-simple.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml.crypto
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.xml.crypto/santuario.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.localedata/thaidict.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.sql.rowset
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.net.http
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.rmi
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.sql
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.naming
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.datatransfer
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.internal.le/jline.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.crypto.cryptoki/pkcs11cryptotoken.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.crypto.cryptoki/pkcs11wrapper.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.instrument
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.management.rmi
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/xwd.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/mesa3d.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/harfbuzz.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/lcms.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/freetype.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/giflib.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/jpeg.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/colorimaging.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/java.desktop/libpng.md
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/legal/jdk.crypto.ec/ecc.md
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/server
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/server/libjsig.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/server/classes.jsa
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/server/classes_nocoops.jsa
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/server/libjvm.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libawt.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libawt_headless.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libsplashscreen.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libnio.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjdwp.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libj2pcsc.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjli.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libsctp.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjimage.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjsig.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjava.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libsunec.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/liblcms.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libawt_xawt.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jexec
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libverify.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libmanagement_agent.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/psfont.properties.ja
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libprefs.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libzip.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjaas.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjsound.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libextnet.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libj2gss.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/tzdb.dat
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libdt_socket.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/psfontj2d.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jvm.cfg
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/ct.sym
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libj2pkcs11.so
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jfr
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jfr/default.jfc
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jfr/profile.jfc
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libmanagement_ext.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/classlist
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libnet.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjavajpeg.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libfontmanager.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/modules
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libinstrument.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libmanagement.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libjawt.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libsaproc.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libmlib_image.so
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/security
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/security/cacerts
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/security/blacklisted.certs
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/security/public_suffix_list.dat
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/security/default.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/librmi.so
%attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jspawnhelper
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/jrt-fs.jar
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libattach.so
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/lib/libfreetype.so
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/jvmti.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/classfile_constants.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/jdwpTransport.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/jawt.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/jni.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/jvmticmlr.h
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/linux
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/linux/jawt_md.h
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/include/linux/jni_md.h
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/net.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/sound.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/sdp
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/sdp/sdp.conf.template
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/management
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/management/management.properties
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/management/jmxremote.access
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/management/jmxremote.password.template
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/logging.properties
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/java.policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/limited
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/limited/default_US_export.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/limited/exempt_local.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/limited/default_local.policy
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/unlimited
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/unlimited/default_US_export.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/unlimited/default_local.policy
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/policy/README.txt
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/conf/security/java.security
%dir %attr(750, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.unsupported.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.transaction.xa.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.crypto.cryptoki.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.rmi.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.attach.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jshell.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.xml.dom.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.se.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.ed.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jartool.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.compiler.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.base.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.smartcardio.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.security.auth.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.unsupported.desktop.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.security.sasl.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.incubator.foreign.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.management.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.management.agent.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.xml.crypto.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.vm.ci.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.prefs.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.crypto.ec.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.jvmstat.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.sql.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.incubator.jpackage.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.xml.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.security.jgss.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.compiler.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.sctp.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.charsets.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.management.jfr.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jlink.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.localedata.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jsobject.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.net.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.hotspot.agent.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jstatd.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.dynalink.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jfr.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.naming.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.le.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jcmd.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.management.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.net.http.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.logging.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.accessibility.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.opt.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.management.rmi.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.security.jgss.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.desktop.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.nio.mapmode.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.vm.compiler.management.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jdwp.agent.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jdi.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.javadoc.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.naming.rmi.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.naming.dns.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.editpad.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jdeps.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.internal.vm.compiler.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.sql.rowset.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.scripting.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.datatransfer.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.httpserver.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.zipfs.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.aot.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/jdk.jconsole.jmod
%attr(640, %{USER}, %{GROUP}) %{INSTALL_DIR}/jdk/jmods/java.instrument.jmod

# -----------------------------------------------------------------------------

%changelog
* Mon Nov 01 2021 support <info@wazuh.com> - 4.3.0
- More info: https://documentation.wazuh.com/current/release-notes/
