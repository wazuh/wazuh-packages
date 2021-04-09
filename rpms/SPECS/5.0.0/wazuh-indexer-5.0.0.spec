Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-indexer
Version:     5.0.0
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
AutoReqProv: no

Requires: coreutils initscripts
BuildRequires: tar

ExclusiveOS: linux


%global USER wazuh-indexer
%global GROUP wazuh-indexer
%global SERVICE_NAME wazuh-indexer
%global CONFIG_DIR /etc/%{SERVICE_NAME}
%global LOG_DIR /var/log/%{SERVICE_NAME}
%global LIB_DIR /var/lib/%{SERVICE_NAME}
%global PID_DIR /var/run/%{SERVICE_NAME}
%global INSTALL_DIR /usr/share/%{SERVICE_NAME}
%global ODFE_VERSION 1.13.1
%global DOCUMENTATION_BRANCH 679-wazuh-packages_wazuh-indexer
%global PACKAGES_BRANCH 679-wazuh-indexer

# -----------------------------------------------------------------------------

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

# -----------------------------------------------------------------------------

%prep

ODFE_DIR=opendistroforelasticsearch-%{ODFE_VERSION}
ODFE_FILE=${ODFE_DIR}-linux-x64.tar.gz
SYSTEMD_MODULE_FILE=systemd_elasticsearch_module_7.10.2.tgz

# Extract elasticsearch-oss tar.gz file
mkdir -p files/plugins
mkdir -p files/config_files
curl -o files/$ODFE_FILE https://packages-dev.wazuh.com/deps/wazuh-indexer/$ODFE_FILE
curl -o files/$SYSTEMD_MODULE_FILE https://packages-dev.wazuh.com/deps/wazuh-indexer/$SYSTEMD_MODULE_FILE

# Files that were previously stored as elasticsearch-oss-extracted-files.tgz now stored in git.
# Need to find the best way of obtaining them since we don't have a wazuh-indexer repo so we can't get a tarball
# as wazuh agent or manager compilation does. Getting them one by one now:
curl -o files/config_files/etc/init.d/%{SERVICE_NAME} --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/init.d/%{SERVICE_NAME}
curl -o files/config_files/etc/wazuh-indexer/log4j2.properties --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/log4j2.properties
curl -o files/config_files/etc/wazuh-indexer/jvm.options --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/jvm.options
curl -o files/config_files/etc/sysconfig/%{SERVICE_NAME} --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/sysconfig/%{SERVICE_NAME}
curl -o files/config_files/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf
curl -o files/config_files/usr/lib/sysctl.d/%{SERVICE_NAME}.conf --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/usr/lib/sysctl.d/%{SERVICE_NAME}.conf
curl -o files/config_files/usr/lib/systemd/system/%{SERVICE_NAME}.service --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/usr/lib/systemd/system/%{SERVICE_NAME}.service
curl -o files/config_files/usr/lib/systemd/system/opendistro-performance-analyzer.service --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/usr/lib/systemd/system/opendistro-performance-analyzer.service
curl -o files/config_files/systemd-entrypoint --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/systemd-entrypoint

# Demo certificates
curl -o files/config_files/etc/wazuh-indexer/certs/admin-key.pem --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/certs/admin-key.pem
curl -o files/config_files/etc/wazuh-indexer/certs/admin.pem --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/certs/admin.pem
curl -o files/config_files/etc/wazuh-indexer/certs/wazuh-indexer-key.pem --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/certs/wazuh-indexer-key.pem
curl -o files/config_files/etc/wazuh-indexer/certs/wazuh-indexer.pem --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/certs/wazuh-indexer.pem
curl -o files/config_files/etc/wazuh-indexer/certs/root-ca.pem --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/etc/wazuh-indexer/certs/root-ca.pem

curl -o files/wazuh-cert-tool.sh https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -o files/instances.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/tools/certificate-utility/instances_aio.yml
#Using only AIO for the moment
#curl -o files/instances.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/tools/certificate-utility/instances.yml
curl -o files/wazuh-passwords-tool.sh https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/tools/wazuh-passwords-tool.sh


curl -o files/config_files/elasticsearch.yml  https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/elasticsearch/7.x/elasticsearch.yml

curl -o files/config_files/roles.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/elasticsearch/roles/roles.yml
curl -o files/config_files/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/elasticsearch/roles/roles_mapping.yml
curl -o files/config_files/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/%{DOCUMENTATION_BRANCH}/resources/open-distro/elasticsearch/roles/internal_users.yml

tar -zvxf files/$ODFE_FILE
tar -zvxf files/$SYSTEMD_MODULE_FILE -C $ODFE_DIR/modules

# Fix distribution type so systemd is notified: https://github.com/elastic/elasticsearch/issues/55477
sed -i 's/ES_DISTRIBUTION_TYPE=tar/ES_DISTRIBUTION_TYPE=rpm/' $ODFE_DIR/bin/elasticsearch-env



# -----------------------------------------------------------------------------

%install

ODFE_DIR=opendistroforelasticsearch-%{ODFE_VERSION}

# Clean BUILDROOT
rm -fr %{buildroot}

# Create directories
mkdir -p %{buildroot}%{_initrddir}
mkdir -p %{buildroot}%{_localstatedir}
mkdir -p %{buildroot}%{CONFIG_DIR}/certs
mkdir -p %{buildroot}%{CONFIG_DIR}/jvm.options.d
mkdir -p %{buildroot}/etc/init.d
mkdir -p %{buildroot}/etc/sysconfig
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
mkdir -p %{buildroot}/usr/lib/sysctl.d
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}%{LIB_DIR}
mkdir -p %{buildroot}%{LOG_DIR}

# Copy the installed files into buildroot directory
cp -pr $ODFE_DIR/* %{buildroot}%{_localstatedir}/

# Add custom tools
cp files/wazuh-passwords-tool.sh %{buildroot}%{_localstatedir}/bin
cp files/wazuh-cert-tool.sh %{buildroot}%{_localstatedir}/bin
cp files/instances.yml %{buildroot}%{_localstatedir}/bin

# Copy configuration files from documentation repo
cp files/config_files/elasticsearch.yml %{buildroot}%{CONFIG_DIR}/elasticsearch.yml

# Copy configuration files for wazuh-indexer
cp files/config_files/etc/init.d/%{SERVICE_NAME} %{buildroot}/etc/init.d/%{SERVICE_NAME}
cp files/config_files/etc/wazuh-indexer/log4j2.properties %{buildroot}%{CONFIG_DIR}/log4j2.properties
cp files/config_files/etc/wazuh-indexer/jvm.options %{buildroot}%{CONFIG_DIR}/jvm.options
cp files/config_files/etc/sysconfig/%{SERVICE_NAME} %{buildroot}/etc/sysconfig/%{SERVICE_NAME}
cp files/config_files/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf %{buildroot}/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf
cp files/config_files/usr/lib/sysctl.d/%{SERVICE_NAME}.conf %{buildroot}/usr/lib/sysctl.d/%{SERVICE_NAME}.conf
cp files/config_files/usr/lib/systemd/system/%{SERVICE_NAME}.service %{buildroot}/usr/lib/systemd/system/%{SERVICE_NAME}.service
cp files/config_files/systemd-entrypoint %{buildroot}%{_localstatedir}/bin

# Service for performance analyzer
cp files/config_files/usr/lib/systemd/system/opendistro-performance-analyzer.service %{buildroot}/usr/lib/systemd/system/

# This is needed by the performance-analyzer service
echo false > %{buildroot}%{_localstatedir}/data/batch_metrics_enabled.conf

# Copy certificates
cp files/config_files/etc/wazuh-indexer/certs/admin-key.pem %{buildroot}%{CONFIG_DIR}/certs/admin-key.pem
cp files/config_files/etc/wazuh-indexer/certs/admin.pem %{buildroot}%{CONFIG_DIR}/certs/admin.pem
cp files/config_files/etc/wazuh-indexer/certs/wazuh-indexer-key.pem %{buildroot}%{CONFIG_DIR}/certs/wazuh-indexer-key.pem
cp files/config_files/etc/wazuh-indexer/certs/wazuh-indexer.pem %{buildroot}%{CONFIG_DIR}/certs/wazuh-indexer.pem
cp files/config_files/etc/wazuh-indexer/certs/root-ca.pem %{buildroot}%{CONFIG_DIR}/certs/root-ca.pem


# Run the opendistro tar install script but don't start elasticsearch at this time
sed -i 's/bash $ES_HOME/#bash $ES_HOME/' %{buildroot}%{_localstatedir}/opendistro-tar-install.sh

# realpath is not present in docker image generated by rpms/CentOS/6/x86_64/Dockerfile
# One possibility could be to install coreutils in it
# but readlink is present and does the same job, replacing it as a workaround for the moment
sed -i 's/realpath/readlink -f/' %{buildroot}%{_localstatedir}/opendistro-tar-install.sh

export ES_HOME=%{buildroot}%{_localstatedir}
export JAVA_HOME=%{buildroot}%{_localstatedir}/jdk

%{buildroot}%{_localstatedir}/opendistro-tar-install.sh


# Copy Wazuh's config files for the opendistro_security plugin
cp -pr files/config_files/roles_mapping.yml %{buildroot}%{_localstatedir}/plugins/opendistro_security/securityconfig/roles_mapping.yml
cp -pr files/config_files/roles.yml %{buildroot}%{_localstatedir}/plugins/opendistro_security/securityconfig/roles.yml
cp -pr files/config_files/internal_users.yml %{buildroot}%{_localstatedir}/plugins/opendistro_security/securityconfig/internal_users.yml

# Fix file sourced file by elasticsearch-env so that it can find the config directory as /etc/elasticsearch
# https://github.com/elastic/elasticsearch/blob/v7.10.2/distribution/src/bin/elasticsearch-env#L81
# https://github.com/elastic/elasticsearch/blob/v7.10.2/distribution/build.gradle#L585
sed -i 's/if \[ -z "$ES_PATH_CONF" \]; then ES_PATH_CONF="$ES_HOME"\/config; fi/source \/etc\/sysconfig\/wazuh-indexer/' %{buildroot}%{_localstatedir}/bin/elasticsearch-env

# Remove bundled configuration directory since /etc/wazuh-indexer will be used
rm -rf %{buildroot}%{_localstatedir}/config

# Fix performance-analyzer plugin files which references elasticsearch path
# Note: For the moment not using variable because of escaped slashes, but should use INSTALL_DIR
sed -i 's/\/usr\/share\/elasticsearch/\/usr\/share\/wazuh-indexer/' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/pa_config/supervisord.conf
sed -i 's/\/usr\/share\/elasticsearch/\/usr\/share\/wazuh-indexer/' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/supervisord.conf

# Fix performance analyzer JAVA_HOME definition when running manually for non systemd environments
sed -i s'/JAVA_HOME=$2/export JAVA_HOME=$2/' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/pa_bin/performance-analyzer-agent


exit 0

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%%defattr(0644,root,root)


%dir %attr(2750, root, %{GROUP}) "%{CONFIG_DIR}"
%config(noreplace) %attr(0660, root, %{GROUP}) "%{CONFIG_DIR}/elasticsearch.yml"
%config(noreplace) %attr(0660, root, %{GROUP}) "%{CONFIG_DIR}/jvm.options"
%dir %attr(2750, root, %{GROUP}) "%{CONFIG_DIR}/jvm.options.d"
%dir %attr(2750, root, %{GROUP}) "%{CONFIG_DIR}/certs"
%config(noreplace) %attr(0440, root, %{GROUP}) "%{CONFIG_DIR}/certs/admin-key.pem"
%config(noreplace) %attr(0440, root, %{GROUP}) "%{CONFIG_DIR}/certs/admin.pem"
%config(noreplace) %attr(0440, root, %{GROUP}) "%{CONFIG_DIR}/certs/wazuh-indexer-key.pem"
%config(noreplace) %attr(0440, root, %{GROUP}) "%{CONFIG_DIR}/certs/wazuh-indexer.pem"
%config(noreplace) %attr(0440, root, %{GROUP}) "%{CONFIG_DIR}/certs/root-ca.pem"
%config(noreplace) %attr(0660, root, %{GROUP}) "%{CONFIG_DIR}/log4j2.properties"
%config(noreplace) %attr(0750, root, root) "/etc/init.d/%{SERVICE_NAME}"
%config(noreplace) %attr(0660, root, %{GROUP}) "/etc/sysconfig/%{SERVICE_NAME}"
%config(noreplace) %attr(0644, root, root) "/usr/lib/sysctl.d/%{SERVICE_NAME}.conf"
%config(noreplace) %attr(0644, root, root) "/usr/lib/systemd/system/%{SERVICE_NAME}.service"
%config(noreplace) %attr(0644, root, root) "/usr/lib/systemd/system/opendistro-performance-analyzer.service"

%attr(0644, root, root) "/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf"

%attr(755, root, root) %{_localstatedir}/bin/systemd-entrypoint

%attr(0644, root, root) "%{_localstatedir}/LICENSE.txt"
%attr(0664, root, root) "%{_localstatedir}/NOTICE.txt"
%attr(0644, root, root) "%{_localstatedir}/README.asciidoc"

%dir %attr(755, root, root) %{_localstatedir}/bin

%attr(750, root, %{GROUP}) %{_localstatedir}/bin/wazuh-passwords-tool.sh
%attr(750, root, %{GROUP}) %{_localstatedir}/bin/wazuh-cert-tool.sh
%attr(640, root, %{GROUP}) %{_localstatedir}/bin/instances.yml

%attr(755, root, root) %{_localstatedir}/bin/elasticsearch
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-cli
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-env
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-env-from-file
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-keystore
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-node
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-plugin
%attr(755, root, root) %{_localstatedir}/bin/elasticsearch-shard

%dir %attr(755, root, root) %{_localstatedir}/lib

%attr(644, root, root) %{_localstatedir}/lib/*.jar

%dir %attr(755, root, root) %{_localstatedir}/lib/tools


%dir %attr(755, root, root) %{_localstatedir}/lib/tools/keystore-cli
%attr(644, root, root) %{_localstatedir}/lib/tools/keystore-cli/*.jar

%dir %attr(755, root, root) %{_localstatedir}/lib/tools/plugin-cli
%attr(644, root, root) %{_localstatedir}/lib/tools/plugin-cli/*.jar


%dir %attr(755, root, root) %{_localstatedir}/modules
%dir %attr(755, root, root) %{_localstatedir}/modules/aggs-matrix-stats
%dir %attr(755, root, root) %{_localstatedir}/modules/analysis-common
%dir %attr(755, root, root) %{_localstatedir}/modules/geo
%dir %attr(755, root, root) %{_localstatedir}/modules/ingest-common
%dir %attr(755, root, root) %{_localstatedir}/modules/ingest-geoip
%dir %attr(755, root, root) %{_localstatedir}/modules/ingest-user-agent
%dir %attr(755, root, root) %{_localstatedir}/modules/kibana
%dir %attr(755, root, root) %{_localstatedir}/modules/lang-expression
%dir %attr(755, root, root) %{_localstatedir}/modules/lang-mustache
%dir %attr(755, root, root) %{_localstatedir}/modules/lang-painless
%dir %attr(755, root, root) %{_localstatedir}/modules/mapper-extras
%dir %attr(755, root, root) %{_localstatedir}/modules/parent-join
%dir %attr(755, root, root) %{_localstatedir}/modules/percolator
%dir %attr(755, root, root) %{_localstatedir}/modules/rank-eval
%dir %attr(755, root, root) %{_localstatedir}/modules/reindex
%dir %attr(755, root, root) %{_localstatedir}/modules/repository-url
%dir %attr(755, root, root) %{_localstatedir}/modules/transport-netty4


%attr(644, root, root) %{_localstatedir}/modules/aggs-matrix-stats/*
%attr(644, root, root) %{_localstatedir}/modules/analysis-common/*
%attr(644, root, root) %{_localstatedir}/modules/geo/*
%attr(644, root, root) %{_localstatedir}/modules/ingest-common/*
%attr(644, root, root) %{_localstatedir}/modules/ingest-geoip/*
%attr(644, root, root) %{_localstatedir}/modules/ingest-user-agent/*
%attr(644, root, root) %{_localstatedir}/modules/kibana/*
%attr(644, root, root) %{_localstatedir}/modules/lang-expression/*
%attr(644, root, root) %{_localstatedir}/modules/lang-mustache/*
%attr(644, root, root) %{_localstatedir}/modules/lang-painless/*
%attr(644, root, root) %{_localstatedir}/modules/mapper-extras/*
%attr(644, root, root) %{_localstatedir}/modules/parent-join/*
%attr(644, root, root) %{_localstatedir}/modules/percolator/*
%attr(644, root, root) %{_localstatedir}/modules/rank-eval/*
%attr(644, root, root) %{_localstatedir}/modules/reindex/*
%attr(644, root, root) %{_localstatedir}/modules/repository-url/*
%attr(644, root, root) %{_localstatedir}/modules/transport-netty4/*


# elasticsearch module extracted from elasticsearch-oss RPM not present in tar.gz
%dir %attr(755, root, root) %{_localstatedir}/modules/systemd
%attr(644, root, root) %{_localstatedir}/modules/systemd/systemd-7.10.2.jar
%attr(644, root, root) %{_localstatedir}/modules/systemd/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/modules/systemd/plugin-descriptor.properties


# Embedded JDK
%dir %attr(0755, root, root) "%{_localstatedir}/jdk"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/bin"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jaotc"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jar"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jarsigner"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/java"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/javac"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/javadoc"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/javap"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jcmd"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jconsole"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jdb"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jdeprscan"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jdeps"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jfr"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jhsdb"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jimage"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jinfo"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jlink"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jmap"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jmod"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jpackage"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jps"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jrunscript"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jshell"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jstack"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jstat"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/jstatd"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/keytool"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/rmid"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/rmiregistry"
%attr(0755, root, root) "%{_localstatedir}/jdk/bin/serialver"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/logging.properties"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/management"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/management/jmxremote.access"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/management/jmxremote.password.template"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/management/management.properties"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/net.properties"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/sdp"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/sdp/sdp.conf.template"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/security"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/java.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/java.security"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/security/policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/README.txt"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/security/policy/limited"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/limited/default_US_export.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/limited/default_local.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/limited/exempt_local.policy"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/conf/security/policy/unlimited"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/unlimited/default_US_export.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/security/policy/unlimited/default_local.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/conf/sound.properties"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/include"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/classfile_constants.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/jawt.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/jdwpTransport.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/jni.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/jvmti.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/jvmticmlr.h"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/include/linux"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/linux/jawt_md.h"
%attr(0644, root, root) "%{_localstatedir}/jdk/include/linux/jni_md.h"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/jmods"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.base.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.compiler.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.datatransfer.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.desktop.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.instrument.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.logging.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.management.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.management.rmi.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.naming.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.net.http.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.prefs.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.rmi.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.scripting.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.se.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.security.jgss.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.security.sasl.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.smartcardio.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.sql.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.sql.rowset.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.transaction.xa.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.xml.crypto.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/java.xml.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.accessibility.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.aot.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.attach.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.charsets.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.compiler.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.crypto.cryptoki.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.crypto.ec.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.dynalink.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.editpad.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.hotspot.agent.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.httpserver.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.incubator.foreign.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.incubator.jpackage.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.ed.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.jvmstat.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.le.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.opt.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.vm.ci.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.vm.compiler.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.internal.vm.compiler.management.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jartool.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.javadoc.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jcmd.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jconsole.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jdeps.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jdi.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jdwp.agent.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jfr.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jlink.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jshell.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jsobject.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.jstatd.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.localedata.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.management.agent.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.management.jfr.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.management.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.naming.dns.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.naming.rmi.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.net.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.nio.mapmode.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.sctp.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.security.auth.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.security.jgss.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.unsupported.desktop.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.unsupported.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.xml.dom.jmod"
%attr(0644, root, root) "%{_localstatedir}/jdk/jmods/jdk.zipfs.jmod"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.base"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/aes.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/asm.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/c-libutl.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/cldr.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/icu.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/public_suffix.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.base/unicode.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.compiler"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.compiler/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.compiler/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.compiler/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.datatransfer"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.datatransfer/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.datatransfer/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.datatransfer/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.desktop"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/colorimaging.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/freetype.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/giflib.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/harfbuzz.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/jpeg.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/lcms.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/libpng.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/mesa3d.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.desktop/xwd.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.instrument"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.instrument/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.instrument/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.instrument/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.logging"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.logging/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.logging/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.logging/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.management"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.management.rmi"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management.rmi/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management.rmi/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management.rmi/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.management/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.naming"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.naming/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.naming/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.naming/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.net.http"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.net.http/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.net.http/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.net.http/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.prefs"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.prefs/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.prefs/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.prefs/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.rmi"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.rmi/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.rmi/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.rmi/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.scripting"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.scripting/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.scripting/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.scripting/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.se"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.se/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.se/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.se/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.security.jgss"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.jgss/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.jgss/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.jgss/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.security.sasl"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.sasl/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.sasl/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.security.sasl/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.smartcardio"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.smartcardio/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.smartcardio/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.smartcardio/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.smartcardio/pcsclite.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.sql"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.sql.rowset"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql.rowset/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql.rowset/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql.rowset/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.sql/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.transaction.xa"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.transaction.xa/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.transaction.xa/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.transaction.xa/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.xml"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/java.xml.crypto"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml.crypto/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml.crypto/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml.crypto/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml.crypto/santuario.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/bcel.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/dom.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/jcup.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/xalan.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/java.xml/xerces.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.accessibility"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.accessibility/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.accessibility/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.accessibility/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.aot"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.aot/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.aot/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.aot/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.attach"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.attach/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.attach/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.attach/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.charsets"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.charsets/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.charsets/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.charsets/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.compiler"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.compiler/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.compiler/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.compiler/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/pkcs11cryptotoken.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.cryptoki/pkcs11wrapper.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.ec"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.ec/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.ec/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.ec/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.crypto.ec/ecc.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.dynalink"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.dynalink/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.dynalink/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.dynalink/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.dynalink/dynalink.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.editpad"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.editpad/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.editpad/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.editpad/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.hotspot.agent"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.hotspot.agent/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.hotspot.agent/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.hotspot.agent/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.httpserver"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.httpserver/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.httpserver/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.httpserver/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.foreign"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.foreign/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.foreign/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.foreign/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.jpackage"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.jpackage/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.jpackage/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.incubator.jpackage/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.ed"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.ed/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.ed/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.ed/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.jvmstat"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.jvmstat/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.jvmstat/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.jvmstat/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.le"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.le/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.le/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.le/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.le/jline.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.opt"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.opt/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.opt/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.opt/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.opt/jopt-simple.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.ci"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.ci/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.ci/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.ci/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler.management"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler.management/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler.management/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler.management/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.internal.vm.compiler/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jartool"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jartool/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jartool/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jartool/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc/jquery.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.javadoc/jqueryUI.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jcmd"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jcmd/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jcmd/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jcmd/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jconsole"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jconsole/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jconsole/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jconsole/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jdeps"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdeps/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdeps/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdeps/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jdi"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdi/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdi/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdi/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jdwp.agent"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdwp.agent/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdwp.agent/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jdwp.agent/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jfr"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jfr/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jfr/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jfr/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jlink"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jlink/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jlink/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jlink/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jshell"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jshell/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jshell/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jshell/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jsobject"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jsobject/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jsobject/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jsobject/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.jstatd"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jstatd/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jstatd/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.jstatd/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata/cldr.md"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.localedata/thaidict.md"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.management"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.management.agent"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.agent/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.agent/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.agent/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.management.jfr"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.jfr/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.jfr/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management.jfr/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.management/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.dns"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.dns/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.dns/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.dns/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.rmi"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.rmi/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.rmi/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.naming.rmi/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.net"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.net/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.net/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.net/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.nio.mapmode"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.nio.mapmode/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.nio.mapmode/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.nio.mapmode/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.sctp"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.sctp/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.sctp/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.sctp/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.security.auth"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.auth/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.auth/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.auth/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.security.jgss"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.jgss/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.jgss/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.security.jgss/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported.desktop"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported.desktop/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported.desktop/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported.desktop/LICENSE"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.unsupported/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.xml.dom"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.xml.dom/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.xml.dom/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.xml.dom/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/legal/jdk.zipfs"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.zipfs/ADDITIONAL_LICENSE_INFO"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.zipfs/ASSEMBLY_EXCEPTION"
%attr(0644, root, root) "%{_localstatedir}/jdk/legal/jdk.zipfs/LICENSE"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/lib"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/classlist"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/ct.sym"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/jexec"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/lib/jfr"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/jfr/default.jfc"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/jfr/profile.jfc"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/jrt-fs.jar"
%attr(0755, root, root) "%{_localstatedir}/jdk/lib/jspawnhelper"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/jvm.cfg"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libattach.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libawt.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libawt_headless.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libawt_xawt.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libdt_socket.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libextnet.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libfontmanager.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libfreetype.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libinstrument.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libj2gss.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libj2pcsc.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libj2pkcs11.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjaas.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjava.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjavajpeg.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjawt.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjdwp.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjimage.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjli.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjsig.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libjsound.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/liblcms.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libmanagement.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libmanagement_agent.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libmanagement_ext.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libmlib_image.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libnet.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libnio.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libprefs.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/librmi.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libsaproc.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libsctp.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libsplashscreen.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libsunec.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libverify.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/libzip.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/modules"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/psfont.properties.ja"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/psfontj2d.properties"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/lib/security"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/security/blacklisted.certs"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/security/cacerts"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/security/default.policy"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/security/public_suffix_list.dat"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/lib/server"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/server/classes.jsa"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/server/classes_nocoops.jsa"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/server/libjsig.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/server/libjvm.so"
%attr(0644, root, root) "%{_localstatedir}/jdk/lib/tzdb.dat"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/man"
%dir %attr(0755, root, root) "%{_localstatedir}/jdk/man/man1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jaotc.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jar.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jarsigner.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/java.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/javac.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/javadoc.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/javap.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jcmd.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jconsole.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jdb.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jdeprscan.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jdeps.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jfr.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jhsdb.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jinfo.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jlink.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jmap.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jmod.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jpackage.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jps.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jrunscript.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jshell.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jstack.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jstat.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/jstatd.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/keytool.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/rmid.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/rmiregistry.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/man/man1/serialver.1"
%attr(0644, root, root) "%{_localstatedir}/jdk/release"


# Plugins
%dir %attr(755, root, root) %{_localstatedir}/plugins

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-alerting
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-alerting/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-alerting/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-alerting/plugin-descriptor.properties

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-sql
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-sql/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-sql/NOTICE.txt
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-sql/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-sql/plugin-descriptor.properties
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-sql/LICENSE.txt

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-job-scheduler
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-job-scheduler/*

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-anomaly-detection
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-anomaly-detection/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-anomaly-detection/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-anomaly-detection/plugin-descriptor.properties

%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/*.jar
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/plugin-security.policy
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/plugin-descriptor.properties
%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/roles_mapping.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/roles.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/elasticsearch.yml.example
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/tenants.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/internal_users.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/config.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/action_groups.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/whitelist.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/audit.yml
%attr(640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/nodes_dn.yml
%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/securityadmin.sh
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/audit_config_migrater.bat
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/hash.sh
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/install_demo_configuration.sh
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/securityadmin.bat
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/hash.bat
%attr(750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/audit_config_migrater.sh

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-index-management
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-index-management/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-index-management/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-index-management/plugin-descriptor.properties

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/plugin-descriptor.properties
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/pa_config
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/pa_config/*
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/extensions
%attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/extensions/performance-analyzer-agent
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/rpm
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/rpm/postinst
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/rpm/postrm
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/deb
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/deb/postinst
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/install/deb/postrm


%attr(755, root, root) %{_localstatedir}/bin/performance-analyzer-agent-cli
%attr(755, root, root) %{_localstatedir}/opendistro-tar-install.sh


%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/bin
%attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/bin/performance-analyzer-rca
%attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/bin/performance-analyzer-rca.bat
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_bin
%attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_bin/performance-analyzer-agent
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/*
%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/lib
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/lib/*.jar

%dir %attr(755, root, root) %{_localstatedir}/performance-analyzer-rca
%dir %attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/bin
%attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/bin/performance-analyzer-rca
%attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/bin/performance-analyzer-rca.bat
%dir %attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/pa_bin
%attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/pa_bin/performance-analyzer-agent
%dir %attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/pa_config
%attr(644, root, root) %{_localstatedir}/performance-analyzer-rca/pa_config/*
%dir %attr(755, root, root) %{_localstatedir}/performance-analyzer-rca/lib
%attr(644, root, root) %{_localstatedir}/performance-analyzer-rca/lib/*.jar


%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/pa_bin
%attr(755, root, root) %{_localstatedir}/plugins/opendistro-performance-analyzer/pa_bin/performance-analyzer-agent

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-reports-scheduler
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-reports-scheduler/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-reports-scheduler/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-reports-scheduler/plugin-descriptor.properties

%dir %attr(755, root, root) %{_localstatedir}/plugins/opendistro-asynchronous-search
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-asynchronous-search/*.jar
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-asynchronous-search/plugin-security.policy
%attr(644, root, root) %{_localstatedir}/plugins/opendistro-asynchronous-search/plugin-descriptor.properties


# KNN Plugin
%dir %attr(0755, root, root) "%{_localstatedir}/plugins/opendistro-knn"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/checker-qual-2.11.1.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/error_prone_annotations-2.3.4.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/failureaccess-1.0.1.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/guava-29.0-jre.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/j2objc-annotations-1.3.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/jsr305-3.0.2.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/opendistro-knn-1.13.0.0.jar"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/plugin-descriptor.properties"
%attr(0644, root, root) "%{_localstatedir}/plugins/opendistro-knn/plugin-security.policy"

# KNN Lib
%attr(0755, root, root) "%{_localstatedir}/plugins/opendistro-knn/knn-lib/libKNNIndexV2_0_11.so"

%attr(0644, root, root) "%{_localstatedir}/data/batch_metrics_enabled.conf"

%dir %attr(2750, %{USER}, %{GROUP}) "%{LIB_DIR}"
%dir %attr(2750, %{USER}, %{GROUP}) "%{LOG_DIR}"




### The following are scripts were copied from rpmrebuild -s of elasticsearch-oss and adapted to wazuh-indexer


%pre -p /bin/bash
#!/bin/bash
 RPM_ARCH=x86_64 
 RPM_OS=linux 
 RPM_PACKAGE_NAME=%{SERVICE_NAME}
 RPM_PACKAGE_VERSION=7.12.0 
 RPM_PACKAGE_RELEASE=1 

#
# This script is executed in the pre-installation phase
#
#   On Debian,
#       $1=install : indicates an new install
#       $1=upgrade : indicates an upgrade
#
#   On RedHat,
#       $1=1       : indicates an new install
#       $1=2       : indicates an upgrade

err_exit() {
    echo "$@" >&2
    exit 1
}

# source the default env file
if [ -f "/etc/sysconfig/wazuh-indexer" ]; then
    . "/etc/sysconfig/wazuh-indexer"
fi

export ES_PATH_CONF=${ES_PATH_CONF:-%{CONFIG_DIR}}

case "$1" in

    # Debian ####################################################
    install|upgrade)

        # Create wazuh-indexer group if not existing
        if ! getent group %{GROUP} > /dev/null 2>&1 ; then
            echo -n "Creating %{GROUP} group..."
            addgroup --quiet --system %{GROUP}
            echo " OK"
        fi

        # Create wazuh-indexer user if not existing
        if ! id %{USER} > /dev/null 2>&1 ; then
            echo -n "Creating %{USER} user..."
            adduser --quiet \
                    --system \
                    --no-create-home \
                    --home /nonexistent \
                    --ingroup %{GROUP} \
                    --disabled-password \
                    --shell /bin/false \
                    %{USER}
            echo " OK"
        fi
    ;;
    abort-deconfigure|abort-upgrade|abort-remove)
    ;;

    # RedHat ####################################################
    1|2)

        # Create wazuh-indexer group if not existing
        if ! getent group %{GROUP} > /dev/null 2>&1 ; then
            echo -n "Creating %{GROUP} group..."
            groupadd -r %{GROUP}
            echo " OK"
        fi

        # Create wazuh-indexer user if not existing
        if ! id %{USER} > /dev/null 2>&1 ; then
            echo -n "Creating %{USER} user..."
            useradd --system \
                    --no-create-home \
                    --home-dir /nonexistent \
                    --gid %{GROUP} \
                    --shell /sbin/nologin \
                    --comment "%{USER} user" \
                    %{USER}
            echo " OK"
        fi
    ;;

    *)
        err_exit "pre install script called with unknown argument \`$1'"
    ;;
esac

# Built for packages-7.10.0 (rpm)

%post -p /bin/sh
 RPM_ARCH=x86_64 
 RPM_OS=linux 
 RPM_PACKAGE_NAME=%{SERVICE_NAME} 
 RPM_PACKAGE_VERSION=7.12.0 
 RPM_PACKAGE_RELEASE=1 

#
# This script is executed in the post-installation phase
#
#   On Debian,
#       $1=configure : is set to 'configure' and if $2 is set, it is an upgrade
#
#   On RedHat,
#       $1=0         : indicates a removal
#       $1=1         : indicates an upgrade

# source the default env file
if [ -f "/etc/sysconfig/%{SERVICE_NAME}" ]; then
    . "/etc/sysconfig/%{SERVICE_NAME}"
fi

export ES_PATH_CONF=${ES_PATH_CONF:-%{CONFIG_DIR}}

IS_UPGRADE=false

case "$1" in

    # Debian ####################################################
    configure)

        # If $1=configure and $2 is set, this is an upgrade
        if [ -n $2 ]; then
            IS_UPGRADE=true
        fi
        PACKAGE=deb
    ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        PACKAGE=deb
    ;;

    # RedHat ####################################################
    1)
        # If $1=1 this is an install
        IS_UPGRADE=false
        PACKAGE=rpm
    ;;
    2)
        # If $1=1 this is an upgrade
        IS_UPGRADE=true
        PACKAGE=rpm
    ;;

    *)
        echo "post install script called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

# to pick up /usr/lib/sysctl.d/wazuh-indexer.conf
if command -v systemctl > /dev/null; then
    systemctl restart systemd-sysctl.service || true
fi

# TODO: If we will be starting the service at the end we need to remove this message, or make it conditional
# if we will conditionally start the service
if [ "x$IS_UPGRADE" != "xtrue" ]; then
    if command -v systemctl >/dev/null; then
        echo "### NOT starting on installation, please execute the following statements to configure %{SERVICE_NAME} service to start automatically using systemd"
        echo " sudo systemctl daemon-reload"
        echo " sudo systemctl enable wazuh-indexer.service"
        echo "### You can start %{SERVICE_NAME} service by executing"
        echo " sudo systemctl start %{SERVICE_NAME}.service"

    elif command -v chkconfig >/dev/null; then
        echo "### NOT starting on installation, please execute the following statements to configure %{SERVICE_NAME} service to start automatically using chkconfig"
        echo " sudo chkconfig --add %{SERVICE_NAME}"
        echo "### You can start %{SERVICE_NAME} service by executing"
        echo " sudo service %{SERVICE_NAME} start"

    elif command -v update-rc.d >/dev/null; then
        echo "### NOT starting on installation, please execute the following statements to configure %{SERVICE_NAME} service to start automatically using chkconfig"
        echo " sudo update-rc.d %{SERVICE_NAME} defaults 95 10"
        echo "### You can start %{SERVICE_NAME} service by executing"
        echo " sudo /etc/init.d/%{SERVICE_NAME} start"
    fi
elif [ "$RESTART_ON_UPGRADE" = "true" ]; then

    echo -n "Restarting %{SERVICE_NAME} service..."
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl restart %{SERVICE_NAME}.service || true

    elif [ -x /etc/init.d/%{SERVICE_NAME} ]; then
        if command -v invoke-rc.d >/dev/null; then
            invoke-rc.d %{SERVICE_NAME} stop || true
            invoke-rc.d %{SERVICE_NAME} start || true
        else
            /etc/init.d/%{SERVICE_NAME} restart || true
        fi

    # older suse linux distributions do not ship with systemd
    # but do not have an /etc/init.d/ directory
    # this tries to start the wazuh-indexer service on these
    # as well without failing this script
    elif [ -x /etc/rc.d/init.d/%{SERVICE_NAME} ] ; then
        /etc/rc.d/init.d/%{SERVICE_NAME} restart || true
    fi
    echo " OK"
fi

# the equivalent code for rpm is in posttrans
if [ "$PACKAGE" = "deb" ]; then
    if [ ! -f "${ES_PATH_CONF}"/elasticsearch.keystore ]; then
        %{INSTALL_DIR}/bin/elasticsearch-keystore create
        chown root:%{GROUP} "${ES_PATH_CONF}"/elasticsearch.keystore
        chmod 660 "${ES_PATH_CONF}"/elasticsearch.keystore
        md5sum "${ES_PATH_CONF}"/elasticsearch.keystore > "${ES_PATH_CONF}"/.elasticsearch.keystore.initial_md5sum
    else
        if %{INSTALL_DIR}/bin/elasticsearch-keystore has-passwd --silent ; then
          echo "### Warning: unable to upgrade encrypted keystore" 1>&2
          echo " Please run elasticsearch-keystore upgrade and enter password" 1>&2
        else
          %{INSTALL_DIR}/bin/elasticsearch-keystore upgrade
        fi
    fi
fi




## Post install script from opendistro-performance-analyzer plugin
## adapted from plugins/opendistro-performance-analyzer/install/rpm/postinst 

# Post install script for Redhat like distros. Tested on CentOS 7.

echo "Executing postinst"
# Cannot execute the plugin postinst script as suggested in the documentation with this command
#sh %{INSTALL_DIR}/plugins/opendistro-performance-analyzer/install/rpm/postinst 1
# because it contains elasticsearch instructions that now should be replaced by wazuh-indexer
# Using the modified code here:

# Post install script for Redhat like distros. Tested on CentOS 7.

# Make sure the ES_HOME environment variable is set
if [ -z "$ES_HOME" ]; then
  ES_HOME=%{INSTALL_DIR}
fi

# Prepare the RCA reader process for execution
cp -r "$ES_HOME"/plugins/opendistro-performance-analyzer/performance-analyzer-rca $ES_HOME
if [ -f "$ES_HOME"/bin/opendistro-performance-analyzer/performance-analyzer-agent-cli ]; then
  mv "$ES_HOME"/bin/opendistro-performance-analyzer/performance-analyzer-agent-cli "$ES_HOME"/bin
  rm -rf "$ES_HOME"/bin/opendistro-performance-analyzer
fi
mkdir -p "%{LIB_DIR}"
touch "$ES_HOME"/data/rca_enabled.conf
echo 'true' > "$ES_HOME"/data/rca_enabled.conf
echo 'true' > %{LIB_DIR}/performance_analyzer_enabled.conf
echo 'true' > %{LIB_DIR}/rca_enabled.conf
chown %{USER} %{LIB_DIR}/performance_analyzer_enabled.conf
chown %{USER} %{LIB_DIR}/rca_enabled.conf
chown -R %{USER} "$ES_HOME/performance-analyzer-rca"
chmod a+rw /tmp

if ! grep -q '## OpenDistro Performance Analyzer' %{CONFIG_DIR}/jvm.options; then
   CLK_TCK=`/usr/bin/getconf CLK_TCK`
   echo >> %{CONFIG_DIR}/jvm.options
   echo '## OpenDistro Performance Analyzer' >> %{CONFIG_DIR}/jvm.options
   echo "-Dclk.tck=$CLK_TCK" >> %{CONFIG_DIR}/jvm.options
   echo "-Djdk.attach.allowAttachSelf=true" >> %{CONFIG_DIR}/jvm.options
   echo "-Djava.security.policy=file://%{INSTALL_DIR}/plugins/opendistro-performance-analyzer/pa_config/es_security.policy" >> %{CONFIG_DIR}/jvm.options
fi

IS_UPGRADE=false

case "$1" in
    1)
        # If $1=1 this is an install
        IS_UPGRADE=false
    ;;
    2)
        # If $1=2 this is an upgrade
        IS_UPGRADE=true
    ;;

    *)
        echo "post install script called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

if [ "x$IS_UPGRADE" != "xtrue" ]; then
    if command -v systemctl > /dev/null; then
        echo '# Enabling opendistro performance analyzer to start and stop along with elasticsearch.service'
        systemctl daemon-reload
        systemctl enable opendistro-performance-analyzer.service || true

    elif command -v chkconfig >/dev/null; then
        echo "### Non systemd distro. Please start and stop performance analyzer manually using the command: "
        echo "sh %{INSTALL_DIR}/plugins/opendistro-performance-analyzer/pa_bin/performance-analyzer-agent %{INSTALL_DIR} %{INSTALL_DIR}/jdk -d"
    fi
fi



## Remove Elasticsearch demo certificates

rm %{CONFIG_DIR}/esnode-key.pem %{CONFIG_DIR}/esnode.pem %{CONFIG_DIR}/kirk-key.pem %{CONFIG_DIR}/kirk.pem %{CONFIG_DIR}/root-ca.pem -f


# Built for packages-7.10.0 (rpm)

%posttrans -p /bin/sh
 RPM_ARCH=x86_64 
 RPM_OS=linux 
 RPM_PACKAGE_NAME=%{SERVICE_NAME}
 RPM_PACKAGE_VERSION=7.12.0 
 RPM_PACKAGE_RELEASE=1 

# source the default env file
if [ -f "/etc/sysconfig/%{SERVICE_NAME}" ]; then
    . "/etc/sysconfig/%{SERVICE_NAME}"
fi

export ES_PATH_CONF=${ES_PATH_CONF:-%{CONFIG_DIR}}

if [ ! -f "${ES_PATH_CONF}"/elasticsearch.keystore ]; then
    %{INSTALL_DIR}/bin/elasticsearch-keystore create
    chown root:%{GROUP} "${ES_PATH_CONF}"/elasticsearch.keystore
    chmod 660 "${ES_PATH_CONF}"/elasticsearch.keystore
    md5sum "${ES_PATH_CONF}"/elasticsearch.keystore > "${ES_PATH_CONF}"/.elasticsearch.keystore.initial_md5sum
else
    if %{INSTALL_DIR}/bin/elasticsearch-keystore has-passwd --silent ; then
      echo "### Warning: unable to upgrade encrypted keystore" 1>&2
      echo " Please run elasticsearch-keystore upgrade and enter password" 1>&2
    else
      %{INSTALL_DIR}/bin/elasticsearch-keystore upgrade
    fi
fi


# Built for packages-7.10.0 (rpm)

%preun -p /bin/sh
 RPM_ARCH=x86_64 
 RPM_OS=linux 
 RPM_PACKAGE_NAME=%{SERVICE_NAME} 
 RPM_PACKAGE_VERSION=7.12.0 
 RPM_PACKAGE_RELEASE=1 

#
# This script is executed in the pre-remove phase
#
#   On Debian,
#       $1=remove    : indicates a removal
#       $1=upgrade   : indicates an upgrade
#
#   On RedHat,
#       $1=0         : indicates a removal
#       $1=1         : indicates an upgrade

# source the default env file
if [ -f "/etc/sysconfig/%{SERVICE_NAME}" ]; then
    . "/etc/sysconfig/%{SERVICE_NAME}"
fi

export ES_PATH_CONF=${ES_PATH_CONF:-%{CONFIG_DIR}}

STOP_REQUIRED=false
REMOVE_SERVICE=false

case "$1" in

    # Debian ####################################################
    remove)
        STOP_REQUIRED=true
        REMOVE_SERVICE=true
    ;;
    upgrade)
        if [ "$RESTART_ON_UPGRADE" = "true" ]; then
            STOP_REQUIRED=true
        fi
    ;;
    deconfigure|failed-upgrade)
    ;;

    # RedHat ####################################################
    0)
        STOP_REQUIRED=true
        REMOVE_SERVICE=true
    ;;
    1)
        # Dont do anything on upgrade, because the preun script in redhat gets executed after the postinst (madness!)
    ;;

    *)
        echo "pre remove script called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

# Stops the service
if [ "$STOP_REQUIRED" = "true" ]; then
    echo -n "Stopping %{SERVICE_NAME} service..."
    if command -v systemctl >/dev/null; then
        systemctl --no-reload stop %{SERVICE_NAME}.service

    elif [ -x /etc/init.d/%{SERVICE_NAME} ]; then
        if command -v invoke-rc.d >/dev/null; then
            invoke-rc.d %{SERVICE_NAME} stop
        else
            /etc/init.d/%{SERVICE_NAME} stop
        fi

    # older suse linux distributions do not ship with systemd
    # but do not have an /etc/init.d/ directory
    # this tries to start the wazuh-indexer service on these
    # as well without failing this script
    elif [ -x /etc/rc.d/init.d/%{SERVICE_NAME} ] ; then
        /etc/rc.d/init.d/%{SERVICE_NAME} stop
    fi
    echo " OK"
fi

if [ -f "${ES_PATH_CONF}"/%{SERVICE_NAME}.keystore ]; then
  if md5sum --status -c "${ES_PATH_CONF}"/.%{SERVICE_NAME}.keystore.initial_md5sum; then
    rm "${ES_PATH_CONF}"/%{SERVICE_NAME}.keystore "${ES_PATH_CONF}"/.%{SERVICE_NAME}.keystore.initial_md5sum
  fi
fi

if [ "$REMOVE_SERVICE" = "true" ]; then
    if command -v systemctl >/dev/null; then
        systemctl disable %{SERVICE_NAME}.service > /dev/null 2>&1 || true
    fi

    if command -v chkconfig >/dev/null; then
        chkconfig --del %{SERVICE_NAME} 2> /dev/null || true
    fi

    if command -v update-rc.d >/dev/null; then
        update-rc.d %{SERVICE_NAME} remove >/dev/null || true
    fi
fi

# Built for packages-7.10.0 (rpm)

%postun -p /bin/sh
 RPM_ARCH=x86_64 
 RPM_OS=linux 
 RPM_PACKAGE_NAME=%{SERVICE_NAME} 
 RPM_PACKAGE_VERSION=7.12.0 
 RPM_PACKAGE_RELEASE=1 

#
# This script is executed in the post-removal phase
#
#   On Debian,
#       $1=remove    : indicates a removal
#       $1=purge     : indicates an upgrade
#
#   On RedHat,
#       $1=0         : indicates a removal
#       $1=1         : indicates an upgrade

# source the default env file
if [ -f "/etc/sysconfig/%{SERVICE_NAME}" ]; then
    . "/etc/sysconfig/%{SERVICE_NAME}"
fi

export ES_PATH_CONF=${ES_PATH_CONF:-%{CONFIG_DIR}}

REMOVE_DIRS=false
REMOVE_JVM_OPTIONS_DIRECTORY=false
REMOVE_USER_AND_GROUP=false

case "$1" in

    # Debian ####################################################
    remove)
        REMOVE_DIRS=true
    ;;

    purge)
        REMOVE_DIRS=true
        REMOVE_JVM_OPTIONS_DIRECTORY=true
        REMOVE_USER_AND_GROUP=true
    ;;
    failed-upgrade|abort-install|abort-upgrade|disappear|upgrade|disappear)
    ;;

    # RedHat ####################################################
    0)
        REMOVE_DIRS=true
        REMOVE_USER_AND_GROUP=true
    ;;
    1)
        # If $1=1 this is an upgrade
        IS_UPGRADE=true
    ;;

    *)
        echo "post remove script called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

if [ "$REMOVE_DIRS" = "true" ]; then

    if [ -d %{LOG_DIR} ]; then
        echo -n "Deleting log directory..."
        rm -rf %{LOG_DIR}
        echo " OK"
    fi

    if [ -d %{INSTALL_DIR}/plugins ]; then
        echo -n "Deleting plugins directory..."
        rm -rf %{INSTALL_DIR}/plugins
        echo " OK"
    fi

    # plugins may have contained bin files
    if [ -d %{INSTALL_DIR}/bin ]; then
        echo -n "Deleting plugin bin directories..."
        rm -rf %{INSTALL_DIR}/bin
        echo " OK"
    fi

    if [ -d %{PID_DIR} ]; then
        echo -n "Deleting PID directory..."
        rm -rf %{PID_DIR}
        echo " OK"
    fi

    # Delete the data directory if and only if empty
    if [ -d %{LIB_DIR} ]; then
        rmdir --ignore-fail-on-non-empty %{LIB_DIR}
    fi

    # delete the jvm.options.d directory if and only if empty
    if [ -d "${ES_PATH_CONF}/jvm.options.d" ]; then
        rmdir --ignore-fail-on-non-empty "${ES_PATH_CONF}/jvm.options.d"
    fi

    # delete the jvm.options.d directory if we are purging
    if [ "$REMOVE_JVM_OPTIONS_DIRECTORY" = "true" ]; then
      if [ -d "${ES_PATH_CONF}/jvm.options.d" ]; then
        echo -n "Deleting jvm.options.d directory..."
        rm -rf "${ES_PATH_CONF}/jvm.options.d"
        echo " OK"
      fi
    fi

    # delete the conf directory if and only if empty
    if [ -d "${ES_PATH_CONF}" ]; then
        rmdir --ignore-fail-on-non-empty "${ES_PATH_CONF}"
    fi

fi

if [ "$REMOVE_USER_AND_GROUP" = "true" ]; then
    if id %{USER} > /dev/null 2>&1 ; then
        userdel %{USER}
    fi

    if getent group %{GROUP} > /dev/null 2>&1 ; then
        groupdel %{GROUP}
    fi
fi





#### POSTRUN from opendistro-performance-analyzer.spec

# Make sure the ES_HOME environment variable is set
if [ -z "$ES_HOME" ]; then
    ES_HOME=%{INSTALL_DIR}
fi

# Cleanup files
if [ -d $ES_HOME/performance-analyzer-rca ]; then
  rm -rf $ES_HOME/performance-analyzer-rca
fi

if [ -f $ES_HOME/bin/performance-analyzer-agent-cli ]; then
  rm $ES_HOME/bin/performance-analyzer-agent-cli
fi

if [ -f "$ES_HOME"/data/rca_enabled.conf ]; then
  rm "$ES_HOME"/data/rca_enabled.conf
fi

if [ -f "$ES_HOME"/data/batch_metrics_enabled.conf ]; then
  rm "$ES_HOME"/data/batch_metrics_enabled.conf
fi

if [ -f %{LIB_DIR}/performance_analyzer_enabled.conf ]; then
  rm %{LIB_DIR}/performance_analyzer_enabled.conf
fi

if [ -f %{LIB_DIR}/rca_enabled.conf ]; then
  rm %{LIB_DIR}/rca_enabled.conf
fi

if [ -f /usr/lib/systemd/system/opendistro-performance-analyzer.service ]; then
  rm /usr/lib/systemd/system/opendistro-performance-analyzer.service
fi




%changelog
* Mon Apr 26 2021 support <info@wazuh.com> - 5.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
