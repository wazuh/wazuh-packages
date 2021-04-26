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
curl -o files/config_files/usr/lib/systemd/system/wazuh-indexer-performance-analyzer.service --create-dirs https://raw.githubusercontent.com/wazuh/wazuh-packages/%{PACKAGES_BRANCH}/wazuh-indexer/config_files/usr/lib/systemd/system/wazuh-indexer-performance-analyzer.service
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

# Change elasticsearch default ports. Note this could be temporary and could be changed in the repository file
echo "http.port: 9250-9300" >> files/config_files/elasticsearch.yml
echo "transport.tcp.port: 9350-9400" >> files/config_files/elasticsearch.yml

# Change performance analyzer default ports
sed -i 's/webservice-listener-port = 9600/webservice-listener-port = 9601/' $ODFE_DIR/performance-analyzer-rca/pa_config/performance-analyzer.properties
sed -i 's/webservice-listener-port = 9600/webservice-listener-port = 9601/' $ODFE_DIR/plugins/opendistro-performance-analyzer/pa_config/performance-analyzer.properties
sed -i 's/webservice-listener-port = 9600/webservice-listener-port = 9601/' $ODFE_DIR/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/performance-analyzer.properties

sed -i 's/rpc-port = 9650/rpc-port = 9651/' $ODFE_DIR/performance-analyzer-rca/pa_config/performance-analyzer.properties
sed -i 's/rpc-port = 9650/rpc-port = 9651/' $ODFE_DIR/plugins/opendistro-performance-analyzer/pa_config/performance-analyzer.properties
sed -i 's/rpc-port = 9650/rpc-port = 9651/' $ODFE_DIR/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/performance-analyzer.properties

sed -i 's/metrics-location = \/dev\/shm\/performanceanalyzer/metrics-location = \/dev\/shm\/wazuh-indexer-performanceanalyzer/' $ODFE_DIR/performance-analyzer-rca/pa_config/performance-analyzer.properties
sed -i 's/metrics-location = \/dev\/shm\/performanceanalyzer/metrics-location = \/dev\/shm\/wazuh-indexer-performanceanalyzer/' $ODFE_DIR/plugins/opendistro-performance-analyzer/pa_config/performance-analyzer.properties
sed -i 's/metrics-location = \/dev\/shm\/performanceanalyzer/metrics-location = \/dev\/shm\/wazuh-indexer-performanceanalyzer/' $ODFE_DIR/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/performance-analyzer.properties

sed -i 's/metrics-db-file-prefix-path = \/tmp\/metricsdb_/metrics-db-file-prefix-path = \/tmp\/wazuh-indexer_metricsdb_/' $ODFE_DIR/performance-analyzer-rca/pa_config/performance-analyzer.properties
sed -i 's/metrics-db-file-prefix-path = \/tmp\/metricsdb_/metrics-db-file-prefix-path = \/tmp\/wazuh-indexer_metricsdb_/' $ODFE_DIR/plugins/opendistro-performance-analyzer/pa_config/performance-analyzer.properties
sed -i 's/metrics-db-file-prefix-path = \/tmp\/metricsdb_/metrics-db-file-prefix-path = \/tmp\/wazuh-indexer_metricsdb_/' $ODFE_DIR/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/performance-analyzer.properties


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
install -m 0750 files/wazuh-passwords-tool.sh %{buildroot}%{_localstatedir}/bin
install -m 0750 files/wazuh-cert-tool.sh %{buildroot}%{_localstatedir}/bin
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
install -m 0755 files/config_files/systemd-entrypoint %{buildroot}%{_localstatedir}/bin

# Service for performance analyzer
cp files/config_files/usr/lib/systemd/system/wazuh-indexer-performance-analyzer.service %{buildroot}/usr/lib/systemd/system/

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

# Fix performance-analyzer plugin files which references elasticsearch path
sed -i 's!/usr/share/elasticsearch!%{INSTALL_DIR}!g' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/pa_config/supervisord.conf
sed -i 's!/usr/share/elasticsearch!%{INSTALL_DIR}!g' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/performance-analyzer-rca/pa_config/supervisord.conf
sed -i 's!/usr/share/elasticsearch!%{INSTALL_DIR}!g' %{buildroot}%{_localstatedir}/performance-analyzer-rca/pa_config/supervisord.conf

# Fix performance analyzer JAVA_HOME definition when running manually for non systemd environments
sed -i s'/JAVA_HOME=$2/export JAVA_HOME=$2/' %{buildroot}%{_localstatedir}/plugins/opendistro-performance-analyzer/pa_bin/performance-analyzer-agent

# Create group and user in rpmbuild chroot environment so elasticsearch can be started for creating ODFE security indices
groupadd -r %{GROUP}
useradd --system \
                    --no-create-home \
                    --home-dir /nonexistent \
                    --uid 1001 \
                    --gid %{GROUP} \
                    --shell /sbin/nologin \
                    --comment "%{USER} user" \
                    %{USER}


# Copy /etc/wazuh-indexer configuration to local ES config directory to be tuned for starting while building the
# RPM and then this config directory will be cleared
cp -r %{buildroot}%{CONFIG_DIR}/* %{buildroot}%{_localstatedir}/config

sed -i 's!/var/!%{buildroot}/var/!'  %{buildroot}%{_localstatedir}/config/elasticsearch.yml
sed -i 's!%{CONFIG_DIR}/!%{buildroot}%{_localstatedir}/config/!'  %{buildroot}%{_localstatedir}/config/elasticsearch.yml
sed -i 's!/var/!%{buildroot}/var/!'  %{buildroot}%{_localstatedir}/config/jvm.options
sed -i 's!/usr/!%{buildroot}/usr/!'  %{buildroot}%{_localstatedir}/config/jvm.options

chown root:wazuh-indexer %{buildroot}%{_localstatedir}/ -R
chown wazuh-indexer:wazuh-indexer %{buildroot}%{_localstatedir}/config -R
chown wazuh-indexer:wazuh-indexer %{buildroot}/var -R
chown root:wazuh-indexer %{buildroot}/etc -R

echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
echo "wazuh-indexer hard nofile 65535" >> /etc/security/limits.conf
echo "wazuh-indexer soft nofile 65535" >> /etc/security/limits.conf
echo "bootstrap.system_call_filter: false" >> %{buildroot}%{_localstatedir}/config/elasticsearch.yml

sudo -u wazuh-indexer ES_PATH_CONF=%{buildroot}%{_localstatedir}/config %{buildroot}%{_localstatedir}/bin/elasticsearch &

sleep 15

chmod +x %{buildroot}%{_localstatedir}/plugins/opendistro_security/tools/securityadmin.sh

sudo -u wazuh-indexer ES_PATH_CONF=%{buildroot}%{_localstatedir}/config JAVA_HOME=%{buildroot}%{_localstatedir}/jdk %{buildroot}%{_localstatedir}/plugins/opendistro_security/tools/securityadmin.sh -cn indexer-cluster -p 9350 -cd %{buildroot}%{_localstatedir}/plugins/opendistro_security/securityconfig/ -nhnv -cacert %{buildroot}%{CONFIG_DIR}/certs/root-ca.pem -cert %{buildroot}%{CONFIG_DIR}/certs/admin.pem -key %{buildroot}%{CONFIG_DIR}/certs/admin-key.pem

sleep 5

killall java

sleep 10

# Fix file sourced file by elasticsearch-env so that it can find the config directory as /etc/elasticsearch
# https://github.com/elastic/elasticsearch/blob/v7.10.2/distribution/src/bin/elasticsearch-env#L81
# https://github.com/elastic/elasticsearch/blob/v7.10.2/distribution/build.gradle#L585
sed -i 's/if \[ -z "$ES_PATH_CONF" \]; then ES_PATH_CONF="$ES_HOME"\/config; fi/source \/etc\/sysconfig\/wazuh-indexer/' %{buildroot}%{_localstatedir}/bin/elasticsearch-env

# Remove bundled configuration directory since /etc/wazuh-indexer will be used
rm -rf %{buildroot}%{_localstatedir}/config

mv %{buildroot}%{LIB_DIR}/nodes %{buildroot}%{_localstatedir}/initial_nodes
rm -f %{buildroot}%{LOG_DIR}/*
rm -f %{buildroot}%{LIB_DIR}/batch_metrics_enabled.conf
rm -f %{buildroot}%{LIB_DIR}/logging_enabled.conf
rm -f %{buildroot}%{LIB_DIR}/performance_analyzer_enabled.conf
rm -f %{buildroot}%{LIB_DIR}/rca_enabled.conf
rm -f %{buildroot}%{_localstatedir}/opendistro-tar-install.sh

exit 0

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%defattr(-,root,root,0755)

# Configuration files, located outsie of the installation directory
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
%config(noreplace) %attr(0660, root, %{GROUP}) "/etc/sysconfig/%{SERVICE_NAME}"
%attr(0750, root, root) "/etc/init.d/%{SERVICE_NAME}"
%attr(0644, root, root) "/usr/lib/sysctl.d/%{SERVICE_NAME}.conf"
%attr(0644, root, root) "/usr/lib/systemd/system/%{SERVICE_NAME}.service"
%attr(0644, root, root) "/usr/lib/systemd/system/wazuh-indexer-performance-analyzer.service"
%attr(0644, root, root) "/usr/lib/tmpfiles.d/%{SERVICE_NAME}.conf"

# Data folders
%dir %attr(2750, %{USER}, %{GROUP}) "%{LIB_DIR}"
%dir %attr(2750, %{USER}, %{GROUP}) "%{LOG_DIR}"


%dir %{_localstatedir}
%{_localstatedir}/bin
%{_localstatedir}/data
%{_localstatedir}/initial_nodes
%{_localstatedir}/jdk
%{_localstatedir}/lib
%{_localstatedir}/LICENSE.txt
%{_localstatedir}/logs
%{_localstatedir}/modules
%{_localstatedir}/NOTICE.txt
%attr(-, %{USER}, %{GROUP}) %{_localstatedir}/performance-analyzer-rca
%dir %{_localstatedir}/plugins
%{_localstatedir}/plugins/opendistro-alerting
%{_localstatedir}/plugins/opendistro-anomaly-detection
%{_localstatedir}/plugins/opendistro-asynchronous-search
%{_localstatedir}/plugins/opendistro-index-management
%{_localstatedir}/plugins/opendistro-job-scheduler
%{_localstatedir}/plugins/opendistro-knn
%{_localstatedir}/plugins/opendistro-performance-analyzer
%{_localstatedir}/plugins/opendistro-reports-scheduler
%{_localstatedir}/plugins/opendistro-sql
%{_localstatedir}/README.asciidoc

# Change ownership and permissions for security plugin as they are set by its RPM
%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/*.jar
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/plugin-security.policy
%attr(644, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/plugin-descriptor.properties
%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig
%attr(0640, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/securityconfig/*
%dir %attr(755, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools
%attr(0750, root, %{GROUP}) %{_localstatedir}/plugins/opendistro_security/tools/*




### The following scripts are based on elasticsearch-oss and opendistro-performance-analyzer scripts and adapted to wazuh-indexer

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
if [ -f "/etc/sysconfig/%{SERVICE_NAME}" ]; then
    . "/etc/sysconfig/%{SERVICE_NAME}"
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

if [ ! -d "%{LIB_DIR}/nodes" ]; then
    cp -r %{INSTALL_DIR}/initial_nodes %{LIB_DIR}/nodes
    chown %{USER}:%{GROUP} %{LIB_DIR}/nodes -R
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


# Service restart is done after performance analyzer setup

## Here starts the post install script for performance analyzer

## Post install script from opendistro-performance-analyzer plugin
## adapted from plugins/opendistro-performance-analyzer/install/rpm/postinst 

# Post install script for Redhat like distros. Tested on CentOS 7.

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

# Opendistro tar already includes performance-analyzer-rca in the home directory, so this is not necessary
#cp -r "$ES_HOME"/plugins/opendistro-performance-analyzer/performance-analyzer-rca $ES_HOME

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

# Added to avoid excessive logs
echo 'false' > "$ES_HOME"/data/batch_metrics_enabled.conf

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
        systemctl enable wazuh-indexer-performance-analyzer.service || true

    elif command -v chkconfig >/dev/null; then
        echo "### Non systemd distro. Please start and stop performance analyzer manually using the command: "
        echo "sh %{INSTALL_DIR}/plugins/opendistro-performance-analyzer/pa_bin/performance-analyzer-agent %{INSTALL_DIR} %{INSTALL_DIR}/jdk -d"
    fi
fi

## Here ends the post install script for performance analyzer


## Remove Elasticsearch demo certificates

rm %{CONFIG_DIR}/esnode-key.pem %{CONFIG_DIR}/esnode.pem %{CONFIG_DIR}/kirk-key.pem %{CONFIG_DIR}/kirk.pem %{CONFIG_DIR}/root-ca.pem -f


# wazuh-indexer service restart if needed or display commands for manual start

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

if [ -f "${ES_PATH_CONF}"/elasticsearch.keystore ]; then
  if md5sum --status -c "${ES_PATH_CONF}"/.elasticsearch.keystore.initial_md5sum; then
    rm "${ES_PATH_CONF}"/elasticsearch.keystore "${ES_PATH_CONF}"/.elasticsearch.keystore.initial_md5sum
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

# Make sure the ES_HOME environment variable is set
if [ -z "$ES_HOME" ]; then
    ES_HOME=%{INSTALL_DIR}
fi

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

    if [ -f "$ES_HOME"/data/rca_enabled.conf ]; then
        rm "$ES_HOME"/data/rca_enabled.conf
    fi

    if [ -f "$ES_HOME"/data/batch_metrics_enabled.conf ]; then
        rm "$ES_HOME"/data/batch_metrics_enabled.conf
    fi

    # delete the data directory if and only if empty
    if [ -d "$ES_HOME"/data ]; then
        rmdir --ignore-fail-on-non-empty "$ES_HOME"/data
    fi

    if [ -f %{LIB_DIR}/performance_analyzer_enabled.conf ]; then
        rm %{LIB_DIR}/performance_analyzer_enabled.conf
    fi

    if [ -f %{LIB_DIR}/rca_enabled.conf ]; then
        rm %{LIB_DIR}/rca_enabled.conf
    fi

    if [ -f %{LIB_DIR}/batch_metrics_enabled.conf ]; then
        rm %{LIB_DIR}/batch_metrics_enabled.conf
    fi

    # delete the install directory if and only if empty
    if [ -d "%{INSTALL_DIR}" ]; then
        rmdir --ignore-fail-on-non-empty "%{INSTALL_DIR}"
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



%changelog
* Mon Apr 26 2021 support <info@wazuh.com> - 5.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
