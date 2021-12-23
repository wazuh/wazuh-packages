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
Obsoletes:   opendistroforelasticsearch elasticsearch-oss opendistro-sql opendistro-security opendistro-reports-scheduler opendistro-performance-analyzer opendistro-knnlib opendistro-knn opendistro-job-scheduler opendistro-index-management opendistro-asynchronous-search opendistro-anomaly-detection opendistro-alerting
AutoReqProv: no
ExclusiveOS: linux

# -----------------------------------------------------------------------------

%description
Wazuh indexer package

# -----------------------------------------------------------------------------

%install
# Clean BUILDROOT
rm -fr %{buildroot}

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}

# Download required sources
curl -kOL https://s3.amazonaws.com/warehouse.wazuh.com/indexer/wazuh-indexer-base-linux-x64.tar.gz
tar xzvf wazuh-indexer-*.tar.gz && rm -f wazuh-indexer-*.tar.gz

# Copy the installed files into RPM_BUILD_ROOT directory
useradd wazuh
chown -R wazuh:wazuh wazuh-indexer-*/*
cp -pr wazuh-indexer-*/* ${RPM_BUILD_ROOT}%{_localstatedir}/


#mv ${RPM_BUILD_ROOT}%{_localstatedir}/config/opensearch.yml ${RPM_BUILD_ROOT}%{_localstatedir}/config/indexer.yml
#find ${RPM_BUILD_ROOT}%{_localstatedir} -type f -exec sed -i 's|opensearch.yml|indexer.yml|g' {} \;

mkdir -p ${RPM_BUILD_ROOT}/etc/sysconfig
echo 'OPENSEARCH_PATH_CONF=%{_localstatedir}' >> ${RPM_BUILD_ROOT}/etc/sysconfig/wazuh-indexer

# -----------------------------------------------------------------------------

%pre
if ! id wazuh &> /dev/null; then
    useradd wazuh
fi

if [ -d /etc/elasticsearch ];then
    cp -r /etc/elasticsearch /tmp/elasticsearch
fi

if [ -d /usr/share/elasticsearch ];then
    cp -r /usr/share/elasticsearch /tmp/elasticsearch_home
fi

# -----------------------------------------------------------------------------

%post

if [ -d /tmp/elasticsearch ];then
    basefolder="/tmp/elasticsearch"
    #echo 'OPENSEARCH_PATH_CONF=%{_localstatedir}' >> /etc/sysconfig/wazuh-indexer
    if [ -f "${basefolder}/elasticsearch.yml" ];then
        mkdir -p %{_localstatedir}/config/certs

        http_pemcert=`grep http.pemcert ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`
        http_pemkey=`grep http.pemkey ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`
        http_pemtrustedcas=`grep http.pemtrustedcas ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`

        transport_pemcert=`grep transport.pemcert ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`
        transport_pemkey=`grep transport.pemkey ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`
        transport_pemtrustedcas=`grep transport.pemtrustedcas ${basefolder}/elasticsearch.yml | cut -d' ' -f2 | tr -d '"'`

        certs_array=($http_pemcert $http_pemkey $http_pemtrustedcas $transport_pemcert $transport_pemkey $transport_pemtrustedcas)

        for item in "${certs_array[@]}"; do
            basename=`basename ${item}`
            if [[ "${item:0:1}" == '/' ]];then
                cp -r ${item} %{_localstatedir}/config/certs/
            else
                cp -r ${basefolder}/${item} %{_localstatedir}/config/certs/
            fi
            sed -i 's|${item}|certs/${basename}|g' ${basefolder}/elasticsearch.yml
        done
    fi

    # Migrate Elastic config to Indexer
    export ES_HOME=/tmp/elasticsearch_home
    export ES_PATH_CONF=/tmp/elasticsearch
    export OPENSEARCH_HOME=%{_localstatedir}
    export OPENSEARCH_PATH_CONF=%{_localstatedir}/config
    yes | %{_localstatedir}/bin/opensearch-upgrade -s
    chown -R wazuh:wazuh %{_localstatedir}/config

    sed -i 's|/etc/elasticsearch|%{_localstatedir}/config|g' %{_localstatedir}/config/opensearch.yml
    sed -i 's|opendistro_|plugins.|g' %{_localstatedir}/config/opensearch.yml
    sed -i 's|internal_elasticsearch|internal_opensearch|g' %{_localstatedir}/config/opensearch.yml

    echo 'plugins.security.system_indices.enabled: true' >> %{_localstatedir}/config/opensearch.yml
    echo 'plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]' >> %{_localstatedir}/config/opensearch.yml

    # Replacing where to store logs
    if grep '/var/log/elasticsearch' %{_localstatedir}/config/opensearch.yml;then
      sed -i 's|/var/log/elasticsearch|logs|g' %{_localstatedir}/config/opensearch.yml
    fi

else
    echo "path.data: /var/lib/elasticsearch" >> ${RPM_BUILD_ROOT}%{_localstatedir}/config/opensearch.yml
fi

if [ -d /var/lib/elasticsearch ];then
    chown -R wazuh:wazuh /var/lib/elasticsearch
fi

rm -rf /tmp/elasticsearch_home
rm -rf /tmp/elasticsearch

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%defattr(-, wazuh, wazuh)
%dir %attr(755, wazuh, wazuh) %{_localstatedir}
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/bin
%attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/bin/performance-analyzer-rca
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/performance-analyzer-rca-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/sqlite-jdbc-3.32.3.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-stub-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/log4j-api-2.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/bcpkix-jdk15on-1.68.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/bcprov-jdk15on-1.68.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/jackson-databind-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/protobuf-java-3.11.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/gson-2.8.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/commons-lang3-3.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/log4j-core-2.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/perfmark-api-0.19.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/guava-28.2-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-core-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-netty-shaded-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-context-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/annotations-4.1.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/animal-sniffer-annotations-1.18.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/jackson-annotations-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/proto-google-common-protos-1.17.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/javax.annotation-api-1.3.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/checker-qual-2.10.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/commons-io-2.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/jooq-3.10.8.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/jackson-core-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-protobuf-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-protobuf-lite-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/grpc-api-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/lib/failureaccess-1.0.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_bin
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_bin/performance-analyzer-agent
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/agent-stats-metadata
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/plugin-stats-metadata
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/performance-analyzer.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/rca_master.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/rca.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/opensearch_security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/log4j2.xml
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/rca_idle_master.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/performance-analyzer-rca/pa_config/supervisord.conf
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/bin
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-shard
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-node
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-keystore
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-plugin
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-cli
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-env
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/performance-analyzer-agent-cli
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-env-from-file
%attr(755, wazuh, wazuh) %{_localstatedir}/bin/opensearch-upgrade
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/lib
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/hppc-0.8.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-highlighter-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-geo-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-spatial-extras-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-cli-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/java-version-checker-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-memory-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/log4j-api-2.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-analyzers-common-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/snakeyaml-1.26.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/joda-time-2.10.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-x-content-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-join-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-plugin-classloader-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jna-5.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jackson-dataformat-smile-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/log4j-core-2.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-suggest-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-launchers-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jackson-dataformat-yaml-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/HdrHistogram-2.1.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-core-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-queries-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-secure-sm-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/lib/tools
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/lib/tools/plugin-cli
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/plugin-cli/bcpg-fips-1.0.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/plugin-cli/opensearch-plugin-cli-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/plugin-cli/bc-fips-1.0.2.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/lib/tools/upgrade-cli
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/upgrade-cli/jackson-annotations-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/upgrade-cli/jackson-databind-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/upgrade-cli/jackson-core-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/upgrade-cli/opensearch-upgrade-cli-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/lib/tools/keystore-cli
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/tools/keystore-cli/keystore-cli-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-queryparser-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-sandbox-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jts-core-1.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jackson-dataformat-cbor-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-grouping-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-misc-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jackson-core-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/t-digest-3.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/opensearch-core-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-backward-codecs-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/spatial4j-0.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/jopt-simple-5.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/lib/lucene-spatial3d-8.10.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/logs
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/config
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/config/opensearch-observability
%attr(660, wazuh, wazuh) %{_localstatedir}/config/opensearch-observability/observability.yml
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/config/opensearch-reports-scheduler
%attr(660, wazuh, wazuh) %{_localstatedir}/config/opensearch-reports-scheduler/reports-scheduler.yml
%attr(660, wazuh, wazuh) %{_localstatedir}/config/jvm.options
%attr(660, wazuh, wazuh) %{_localstatedir}/config/opensearch.yml
%attr(750, wazuh, wazuh) %{_localstatedir}/config/jvm.options.d
%attr(660, wazuh, wazuh) %{_localstatedir}/config/log4j2.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/NOTICE.txt
%attr(644, wazuh, wazuh) %{_localstatedir}/LICENSE.txt
%attr(644, wazuh, wazuh) %{_localstatedir}/README.md
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/opensearch-observability-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/kotlin-stdlib-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/annotations-13.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/kotlin-stdlib-common-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-observability/guava-15.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/jsoup-1.14.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/minimal-json-0.9.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/json-flattener-0.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/kotlin-stdlib-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/annotations-13.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/json-20180813.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/kotlin-stdlib-common-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/opensearch-reports-scheduler-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-reports-scheduler/guava-15.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-beans-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/resilience4j-core-1.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/core-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-expression-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-aop-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/guava-29.0-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/protocol-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-context-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/slf4j-api-1.7.30.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/druid-1.0.15.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/sql-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/opensearch-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/commons-lang3-3.10.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/jackson-databind-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/checker-qual-2.11.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/reindex-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/gson-2.8.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-core-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/antlr4-runtime-4.7.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/json-20180813.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/NOTICE.txt
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/resilience4j-retry-1.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/spring-jcl-5.2.5.RELEASE.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/LICENSE.txt
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/jackson-annotations-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/vavr-match-0.10.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/parent-join-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/vavr-0.10.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/presto-matching-0.240.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/legacy-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/opensearch-ssl-config-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/commons-codec-1.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/opensearch-sql-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/commons-math3-3.6.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/ppl-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/httpcore-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/failureaccess-1.0.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-sql/common-1.2.1.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/ipaddress-5.3.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/annotations-13.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/kotlinx-coroutines-core-1.3.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/opensearch-cross-cluster-replication-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-common-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-jdk7-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-cross-cluster-replication/kotlin-stdlib-jdk8-1.3.72.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/commons-lang-2.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/guava-29.0-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/opensearch-knn-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/checker-qual-2.11.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/plugin-descriptor.properties
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/knnlib
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/knnlib/libopensearchknn_common.so
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/knnlib/libgomp.so.1
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/knnlib/libopensearchknn_nmslib.so
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/knnlib/libopensearchknn_faiss.so
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-knn/failureaccess-1.0.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/ipaddress-5.3.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/kotlin-stdlib-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/annotations-13.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/kotlinx-coroutines-core-jvm-1.3.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/notification-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/kotlin-stdlib-jdk8-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/opensearch-index-management-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/kotlin-stdlib-common-1.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-index-management/kotlin-stdlib-jdk7-1.4.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/sqlite-jdbc-3.32.3.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-stub-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/bcpkix-jdk15on-1.68.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/bcprov-jdk15on-1.68.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/jackson-databind-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/protobuf-java-3.11.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/paranamer-2.8.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/jackson-module-paranamer-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/gson-2.8.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/commons-lang3-3.9.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/perfmark-api-0.19.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/opensearch-performance-analyzer-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/guava-28.2-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-core-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-netty-shaded-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-context-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/annotations-4.1.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/animal-sniffer-annotations-1.18.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/jackson-annotations-2.11.4.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_bin
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_bin/performance-analyzer-agent
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/performance-analyzer.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/rca_master.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/rca.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/agent-stats-metadata
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/plugin-stats-metadata
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/opensearch_security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/log4j2.xml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/rca_idle_master.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/pa_config/supervisord.conf
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/performanceanalyzer-rca-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/proto-google-common-protos-1.17.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/javax.annotation-api-1.3.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/checker-qual-2.10.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/commons-io-2.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/jooq-3.10.8.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-protobuf-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-protobuf-lite-1.28.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/extensions
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/extensions/performance-analyzer-agent
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/grpc-api-1.28.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-performance-analyzer/failureaccess-1.0.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-job-scheduler
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-job-scheduler/opensearch-job-scheduler-spi-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-job-scheduler/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-job-scheduler/opensearch-job-scheduler-1.2.1.0.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-saml-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-codec-1.14.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/java-saml-2.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/slf4j-api-1.7.25.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/minimal-json-0.9.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-security-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.jws-api-2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-codec-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jackson-databind-2.11.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.activation-1.2.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-logging-1.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/json-path-2.4.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/aggs-matrix-stats-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/lang-mustache-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/bcprov-jdk15on-1.67.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/json-flattener-0.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/cxf-rt-rs-json-basic-3.4.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/snappy-java-1.1.7.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-common-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-xmlsec-impl-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/txw2-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/cxf-core-3.4.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jackson-annotations-2.11.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/metrics-core-3.1.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jboss-rmi-api_1.0_spec-1.0.6.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-soap-impl-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/j2objc-annotations-1.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-messaging-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-storage-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-lang-2.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/mapper-extras-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.xml.bind-api-2.3.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-saml-impl-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/java-saml-core-2.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/cryptacular-1.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-core-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-cli-1.3.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jjwt-api-0.10.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/log4j-slf4j-impl-2.15.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-lang3-3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/lz4-java-1.7.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/rank-eval-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/ldaptive-1.2.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.xml.soap-api-1.4.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensearch-security-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jjwt-jackson-0.10.5.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/whitelist.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/tenants.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/nodes_dn.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/audit.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/action_groups.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/config.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/roles_mapping.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/roles.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/opensearch.yml.example
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/securityconfig/internal_users.yml
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/woodstox-core-6.2.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/eventbus-3.2.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/istack-commons-runtime-3.0.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/asm-9.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/parent-join-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jjwt-impl-0.10.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/json-smart-2.4.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/xmlsec-2.2.3.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/securityadmin.bat
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/hash.sh
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/securityadmin.sh
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/audit_config_migrater.sh
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/audit_config_migrater.bat
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/install_demo_configuration.sh
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/tools/hash.bat
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.xml.ws-api-2.3.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/xmlschema-core-2.2.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/httpclient-cache-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/velocity-1.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/error_prone_annotations-2.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-resolver-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/transport-netty4-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/animal-sniffer-annotations-1.14.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/stax-ex-1.8.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/compiler-0.9.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/guava-25.1-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-xmlsec-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/zjsonpatch-0.4.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/accessors-smart-2.4.7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensearch-rest-high-level-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/cxf-rt-security-3.4.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/java-support-7.5.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-transport-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/kafka-clients-2.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/stax2-api-4.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/cxf-rt-rs-security-jose-3.4.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-profile-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jaxb-runtime-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-security-impl-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-collections-3.2.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-buffer-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/saaj-impl-1.5.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/commons-text-1.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/zstd-jni-1.4.4-7.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/jakarta.annotation-api-1.3.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/geronimo-jta_1.1_spec-1.1.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/checker-qual-2.0.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-codec-http-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/httpcore-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/opensaml-soap-api-3.4.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-security/netty-handler-4.1.69.Final.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-asynchronous-search
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-asynchronous-search/opensearch-asynchronous-search-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-asynchronous-search/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-asynchronous-search/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-asynchronous-search/plugin-security.policy
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/commons-lang-2.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/org.jacoco.report-0.8.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/slf4j-api-1.7.25.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/guava-29.0-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/randomcutforest-core-2.0.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/randomcutforest-serialization-2.0.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/jackson-databind-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/checker-qual-2.11.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/randomcutforest-parkservices-2.0.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/gson-2.8.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/protostuff-collectionschema-1.7.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/opensearch-anomaly-detection-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/org.jacoco.ant-0.8.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/commons-pool2-2.10.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/sketches-core-0.13.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/org.jacoco.core-0.8.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/org.jacoco.agent-0.8.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/protostuff-api-1.7.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/memory-0.12.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/jackson-annotations-2.11.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/protostuff-runtime-1.7.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/protostuff-core-1.7.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/commons-logging-1.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/commons-codec-1.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/commons-math3-3.6.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/httpcore-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-anomaly-detection/failureaccess-1.0.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/error_prone_annotations-2.3.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/cron-utils-9.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/javax.mail-1.6.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/slf4j-api-1.7.30.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/ipaddress-5.3.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/j2objc-annotations-1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/commons-lang3-3.11.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/common-utils-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/jsr305-3.0.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/javax.el-3.0.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlinx-coroutines-core-1.1.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/annotations-13.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/guava-30.0-jre.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/activation-1.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/alerting-core-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/google-java-format-1.10.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/alerting-notification-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlin-stdlib-common-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/commons-logging-1.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlin-stdlib-jdk7-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/checker-qual-3.5.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/opensearch-alerting-1.2.1.0.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlinx-coroutines-core-common-1.1.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlin-stdlib-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/commons-codec-1.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/kotlin-stdlib-jdk8-1.3.72.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/httpcore-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/plugins/opensearch-alerting/failureaccess-1.0.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/ingest-common
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/jcodings-1.0.44.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/joni-2.1.29.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/opensearch-grok-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/opensearch-dissect-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-common/ingest-common-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/geo
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/geo/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/geo/geo-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/GeoLite2-Country.mmdb
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/GeoLite2-City.mmdb
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/geoip2-2.13.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/maxmind-db-1.3.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/jackson-annotations-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/jackson-databind-2.12.5.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/ingest-geoip-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/GeoLite2-ASN.mmdb
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-geoip/plugin-security.policy
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/percolator
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/percolator/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/percolator/percolator-client-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/analysis-common
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/analysis-common/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/analysis-common/analysis-common-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/aggs-matrix-stats
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/aggs-matrix-stats/aggs-matrix-stats-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/aggs-matrix-stats/plugin-descriptor.properties
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/repository-url
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/repository-url/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/repository-url/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/repository-url/repository-url-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/lang-mustache
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-mustache/lang-mustache-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-mustache/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-mustache/compiler-0.9.6.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-mustache/plugin-security.policy
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-codec-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-common-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-resolver-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/transport-netty4-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-transport-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-buffer-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-codec-http-4.1.69.Final.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/transport-netty4/netty-handler-4.1.69.Final.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/lang-expression
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/lucene-expressions-8.10.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/lang-expression-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/antlr4-runtime-4.5.1-1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/asm-5.0.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/asm-commons-5.0.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-expression/asm-tree-5.0.4.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/lang-painless
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/asm-7.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/antlr4-runtime-4.5.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/asm-tree-7.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/asm-util-7.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/asm-analysis-7.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/asm-commons-7.2.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/lang-painless-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/lang-painless/opensearch-scripting-painless-spi-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/rank-eval
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/rank-eval/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/rank-eval/rank-eval-client-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/reindex-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/commons-logging-1.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/opensearch-dashboards-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/opensearch-ssl-config-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/commons-codec-1.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/opensearch-dashboards/httpcore-4.4.12.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/ingest-user-agent
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-user-agent/ingest-user-agent-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/ingest-user-agent/plugin-descriptor.properties
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/mapper-extras
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/mapper-extras/mapper-extras-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/mapper-extras/plugin-descriptor.properties
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/parent-join
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/parent-join/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/parent-join/parent-join-client-1.2.1.jar
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/modules/reindex
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/httpcore-nio-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/httpasyncclient-4.1.4.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/reindex-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/plugin-descriptor.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/commons-logging-1.1.3.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/opensearch-rest-client-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/plugin-security.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/httpclient-4.5.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/opensearch-ssl-config-1.2.1.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/commons-codec-1.13.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/modules/reindex/httpcore-4.4.12.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/manifest.yml
%dir %attr(755, wazuh, wazuh) %{_localstatedir}/jdk
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/man
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/man/man1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jrunscript.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jcmd.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/java.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jdeprscan.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/javadoc.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/rmid.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jar.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jdb.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jpackage.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jstatd.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/serialver.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/keytool.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jconsole.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jlink.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jhsdb.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jaotc.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jshell.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/rmiregistry.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/javac.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jstack.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jfr.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jps.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jarsigner.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jmod.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jstat.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jinfo.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jmap.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/jdeps.1
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/man/man1/javap.1
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/bin
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jdeps
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/rmiregistry
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jrunscript
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jdeprscan
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jar
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jmap
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jps
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jstatd
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/rmid
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/java
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jdb
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jimage
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/javadoc
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jconsole
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jcmd
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jstack
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jinfo
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jpackage
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/serialver
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/javap
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/keytool
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jaotc
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jarsigner
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jhsdb
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jlink
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jfr
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jstat
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/javac
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jmod
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/bin/jshell
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/release
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/LICENSE
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/ADDITIONAL_LICENSE_INFO
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/icu.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/c-libutl.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/public_suffix.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/cldr.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/aes.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/ASSEMBLY_EXCEPTION
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/asm.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.base/unicode.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.security.sasl
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.scripting
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.dynalink/dynalink.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.management
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.javadoc/jqueryUI.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.javadoc/jquery.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml/xalan.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml/xerces.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml/jcup.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml/bcel.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml/dom.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.smartcardio
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.smartcardio/pcsclite.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.transaction.xa
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.prefs
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.compiler
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.logging
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.internal.opt/jopt-simple.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml.crypto
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.xml.crypto/santuario.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.localedata/thaidict.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.sql.rowset
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.net.http
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.rmi
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.sql
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.naming
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.datatransfer
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.internal.le/jline.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/pkcs11cryptotoken.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/pkcs11wrapper.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.instrument
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.management.rmi
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/xwd.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/mesa3d.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/harfbuzz.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/lcms.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/freetype.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/giflib.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/jpeg.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/colorimaging.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/java.desktop/libpng.md
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/legal/jdk.crypto.ec/ecc.md
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/lib
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/lib/server
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/server/libjsig.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/server/classes.jsa
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/server/classes_nocoops.jsa
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/server/libjvm.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libawt.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libawt_headless.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libsplashscreen.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libnio.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjdwp.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libj2pcsc.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjli.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libsctp.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjimage.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjsig.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjava.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libsunec.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/liblcms.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libawt_xawt.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/jexec
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libverify.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libmanagement_agent.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/psfont.properties.ja
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libprefs.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libzip.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjaas.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjsound.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libextnet.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libj2gss.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/tzdb.dat
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libdt_socket.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/psfontj2d.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/jvm.cfg
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/ct.sym
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libj2pkcs11.so
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/lib/jfr
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/jfr/default.jfc
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/jfr/profile.jfc
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libmanagement_ext.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/classlist
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libnet.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjavajpeg.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libfontmanager.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/modules
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libinstrument.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libmanagement.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libjawt.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libsaproc.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libmlib_image.so
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/lib/security
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/security/cacerts
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/security/blacklisted.certs
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/security/public_suffix_list.dat
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/security/default.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/librmi.so
%attr(755, wazuh, wazuh) %{_localstatedir}/jdk/lib/jspawnhelper
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/jrt-fs.jar
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libattach.so
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/lib/libfreetype.so
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/include
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/jvmti.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/classfile_constants.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/jdwpTransport.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/jawt.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/jni.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/jvmticmlr.h
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/include/linux
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/linux/jawt_md.h
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/include/linux/jni_md.h
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/net.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/sound.properties
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/sdp
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/sdp/sdp.conf.template
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/management
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/management/management.properties
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/management/jmxremote.access
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/management/jmxremote.password.template
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/logging.properties
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/security
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/java.policy
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/limited
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/limited/default_US_export.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/limited/exempt_local.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/limited/default_local.policy
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/unlimited
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/unlimited/default_US_export.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/unlimited/default_local.policy
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/policy/README.txt
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/conf/security/java.security
%dir %attr(750, wazuh, wazuh) %{_localstatedir}/jdk/jmods
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.unsupported.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.transaction.xa.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.crypto.cryptoki.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.rmi.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.attach.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jshell.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.xml.dom.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.se.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.ed.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jartool.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.compiler.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.base.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.smartcardio.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.security.auth.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.unsupported.desktop.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.security.sasl.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.incubator.foreign.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.management.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.management.agent.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.xml.crypto.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.vm.ci.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.prefs.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.crypto.ec.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.jvmstat.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.sql.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.incubator.jpackage.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.xml.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.security.jgss.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.compiler.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.sctp.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.charsets.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.management.jfr.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jlink.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.localedata.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jsobject.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.net.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.hotspot.agent.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jstatd.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.dynalink.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jfr.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.naming.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.le.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jcmd.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.management.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.net.http.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.logging.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.accessibility.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.opt.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.management.rmi.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.security.jgss.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.desktop.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.nio.mapmode.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.vm.compiler.management.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jdwp.agent.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jdi.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.javadoc.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.naming.rmi.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.naming.dns.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.editpad.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jdeps.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.internal.vm.compiler.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.sql.rowset.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.scripting.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.datatransfer.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.httpserver.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.zipfs.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.aot.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/jdk.jconsole.jmod
%attr(644, wazuh, wazuh) %{_localstatedir}/jdk/jmods/java.instrument.jmod
%attr(644, wazuh, wazuh) /etc/sysconfig/wazuh-indexer

# -----------------------------------------------------------------------------

%changelog
* Mon Nov 01 2021 support <info@wazuh.com> - 4.3.0
- More info: https://documentation.wazuh.com/current/release-notes/
