Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-local
Version:     4.3.11
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(preun):  /sbin/service
Requires(postun): /sbin/service /usr/sbin/groupdel /usr/sbin/userdel
Conflicts:   ossec-hids ossec-hids-agent wazuh-agent wazuh-local wazuh-manager
Obsoletes: wazuh-api < 4.0.0
AutoReqProv: no

Requires: coreutils
BuildRequires: coreutils automake autoconf libtool

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q
set -x
./gen_ossec.sh conf local centos %rhel %{_localstatedir} > etc/ossec-server.conf

%build
# Rebuild for server
cd src
gmake clean

# Build Wazuh sources
deps_version=`cat Makefile | grep "DEPS_VERSION =" | cut -d " " -f 3`
gmake deps TARGET=local RESOURCES_URL=http://packages.wazuh.com/deps/${deps_version}
gmake TARGET=local USE_SELINUX=no DEBUG=%{_debugenabled}

cd ..

%install
# Clean BUILDROOT
rm -fr %{buildroot}

echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="local"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ACTIVE_RESPONSE="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_CISCAT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCOLLECTOR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_EMAIL="n"' >> ./etc/preloaded-vars.conf
echo 'USER_WHITE_LIST="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSLOG="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_AUTHD="y"' >> ./etc/preloaded-vars.conf
echo 'USER_SERVER_IP="MANAGER_IP"' >> ./etc/preloaded-vars.conf
echo 'USER_CA_STORE="/path/to/my_cert.pem"' >> ./etc/preloaded-vars.conf
echo 'USER_GENERATE_AUTHD_CERT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf
echo 'USER_CREATE_SSL_CERT="n"' >> ./etc/preloaded-vars.conf
./install.sh

# Remove unnecessary files or directories
rm -rf %{_localstatedir}/selinux

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_init_scripts}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/.ssh

# Copy the files into RPM_BUILD_ROOT directory
sed "s:WAZUH_HOME_TMP:%{_localstatedir}:g" src/init/templates/ossec-hids-aix.init > src/init/templates/ossec-hids-aix.init.tmp
mv src/init/templates/ossec-hids-aix.init.tmp src/init/templates/ossec-hids-aix.init
/opt/freeware/bin/install -m 0750 src/init/templates/ossec-hids-aix.init ${RPM_BUILD_ROOT}%{_init_scripts}/wazuh-local
cp -pr %{_localstatedir}/* ${RPM_BUILD_ROOT}%{_localstatedir}/

# Install Vulnerability Detector files
/opt/freeware/bin/install -m 0440 src/wazuh_modules/vulnerability_detector/*.json ${RPM_BUILD_ROOT}%{_localstatedir}/queue/vulnerabilities/dictionaries

# Copy scap templates
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/generic/
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/generic

mkdir -p %{RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/src/init
/opt/freeware/bin/install -m 0640 src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/local_installation_scripts/src/

if [ %{_debugenabled} = "yes" ]; then
  %{_rpmconfigdir}/find-debuginfo.sh
fi
exit 0

%pre

# Create the test group if it doesn't exists
if command -v getent > /dev/null 2>&1 && ! getent group test > /dev/null 2>&1; then
  groupadd -r test
elif ! getent group test > /dev/null 2>&1; then
  groupadd -r test
fi

# Create the test user if it doesn't exists
if ! getent passwd test > /dev/null 2>&1; then
  useradd -g test -G test -d %{_localstatedir} -r -s /sbin/nologin test
fi

# Stop the services to upgrade the package
if [ $1 = 2 ]; then
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-local > /dev/null 2>&1; then
    systemctl stop wazuh-local.service > /dev/null 2>&1
    %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-local status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-local stop > /dev/null 2>&1
    %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  elif %{_localstatedir}/bin/wazuh-control status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    touch %{_localstatedir}/tmp/wazuh.restart
  elif %{_localstatedir}/bin/ossec-control status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    touch %{_localstatedir}/tmp/wazuh.restart
  fi
  %{_localstatedir}/bin/ossec-control stop > /dev/null 2>&1 || %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1
fi
if pgrep -f ossec-authd > /dev/null 2>&1; then
    kill -15 $(pgrep -f ossec-authd)
fi


# Remove/relocate existing SQLite databases
rm -f %{_localstatedir}/var/db/cluster.db* || true
rm -f %{_localstatedir}/var/db/.profile.db* || true
rm -f %{_localstatedir}/var/db/agents/* || true

if [ -f %{_localstatedir}/var/db/global.db ]; then
  mv %{_localstatedir}/var/db/global.db %{_localstatedir}/queue/db/
  rm -f %{_localstatedir}/var/db/global.db* || true
  rm -f %{_localstatedir}/var/db/.template.db || true
fi

if [ -f %{_localstatedir}/queue/db/global.db ]; then
  chmod 640 %{_localstatedir}/queue/db/global.db*
  chown test:test %{_localstatedir}/queue/db/global.db*
fi

# Remove Vuln-detector database
rm -f %{_localstatedir}/queue/vulnerabilities/cve.db || true

# Remove plain-text agent information if exists
if [ -d %{_localstatedir}/queue/agent-info ]; then
  rm -rf %{_localstatedir}/queue/agent-info/* > /dev/null 2>&1
fi

if [ -d %{_localstatedir}/queue/rootcheck ]; then
  rm -rf %{_localstatedir}/queue/rootcheck/* > /dev/null 2>&1
fi

# Delete old API backups
if [ $1 = 2 ]; then
  if [ -d %{_localstatedir}/~api ]; then
    rm -rf %{_localstatedir}/~api
  fi

  if [ -f %{_sysconfdir}/ossec-init.conf ]; then
    # Import the variables from ossec-init.conf file
    . %{_sysconfdir}/ossec-init.conf
  else
    # Ask wazuh-control the version
    VERSION=$(%{_localstatedir}/bin/wazuh-control info -v)
  fi

  # Get the major and minor version
  MAJOR=$(echo $VERSION | cut -dv -f2 | cut -d. -f1)
  MINOR=$(echo $VERSION | cut -d. -f2)

  # Delete uncompatible DBs versions
  if [ $MAJOR = 3 ] && [ $MINOR -lt 7 ]; then
    rm -f %{_localstatedir}/queue/db/*.db*
    rm -f %{_localstatedir}/queue/db/.template.db
  fi

  # Delete 3.X Wazuh API service
  if [ "$MAJOR" = "3" ] && [ -d %{_localstatedir}/api ]; then
    if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
      systemctl stop wazuh-api.service > /dev/null 2>&1
      systemctl disable wazuh-api.service > /dev/null 2>&1
      rm -f /etc/systemd/system/wazuh-api.service
    elif command -v service > /dev/null 2>&1 && command -v chkconfig > /dev/null 2>&1; then
      service wazuh-api stop > /dev/null 2>&1
      chkconfig wazuh-api off > /dev/null 2>&1
      chkconfig --del wazuh-api > /dev/null 2>&1
      rm -f /etc/rc.d/init.d/wazuh-api || true
    fi
  fi
fi

%post

echo "VERSION=\"$(%{_localstatedir}/bin/wazuh-control info -v)\"" > /etc/ossec-init.conf
if [ $1 = 2 ]; then
  if [ -d %{_localstatedir}/logs/ossec ]; then
    rm -rf %{_localstatedir}/logs/wazuh
    cp -rp %{_localstatedir}/logs/ossec %{_localstatedir}/logs/wazuh
  fi

  if [ -d %{_localstatedir}/queue/ossec ]; then
    rm -rf %{_localstatedir}/queue/sockets
    cp -rp %{_localstatedir}/queue/ossec %{_localstatedir}/queue/sockets
  fi
fi

# Fresh install code block
if [ $1 = 1 ]; then
  sles=""
  if [ -f /etc/SuSE-release ]; then
    sles="suse"
  elif [ -f /etc/os-release ]; then
    if `grep -q "\"sles" /etc/os-release` ; then
      sles="suse"
    elif `grep -q -i "\"opensuse" /etc/os-release` ; then
      sles="opensuse"
    fi
  fi

  if [ ! -z "$sles" ]; then
    if [ -d /etc/init.d ]; then
      /opt/freeware/bin/install -m 755 %{_localstatedir}/packages_files/local_installation_scripts/src/init/ossec-hids-suse.init /etc/init.d/wazuh-local
    fi
  fi

  . %{_localstatedir}/packages_files/local_installation_scripts/src/init/dist-detect.sh

  # Generating ossec.conf file
  %{_localstatedir}/packages_files/local_installation_scripts/gen_ossec.sh conf local ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir} > %{_localstatedir}/etc/ossec.conf

  touch %{_localstatedir}/logs/active-responses.log
  touch %{_localstatedir}/logs/integrations.log
  chown test:test %{_localstatedir}/logs/active-responses.log
  chown test:test %{_localstatedir}/logs/integrations.log
  chmod 0660 %{_localstatedir}/logs/active-responses.log
  chmod 0640 %{_localstatedir}/logs/integrations.log

  # Add default local_files to ossec.conf
  %{_localstatedir}/packages_files/local_installation_scripts/add_localfiles.sh %{_localstatedir} >> %{_localstatedir}/etc/ossec.conf
fi

if [ -f /etc/os-release ]; then
  source /etc/os-release
  if [ "${NAME}" = "Red Hat Enterprise Linux" ] && [ "$((${VERSION_ID:0:1}))" -ge 9 ]; then
    rm -f %{_initrddir}/wazuh-local
  fi
fi

# Generation auto-signed certificate if not exists
if type openssl >/dev/null 2>&1 && [ ! -f "%{_localstatedir}/etc/ssllocal.key" ] && [ ! -f "%{_localstatedir}/etc/ssllocal.cert" ]; then
  openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout %{_localstatedir}/etc/ssllocal.key -out %{_localstatedir}/etc/ssllocal.cert 2>/dev/null
  chmod 640 %{_localstatedir}/etc/ssllocal.key
  chmod 640 %{_localstatedir}/etc/ssllocal.cert
fi

rm -f %{_localstatedir}/etc/shared/ar.conf  >/dev/null 2>&1
rm -f %{_localstatedir}/etc/shared/merged.mg  >/dev/null 2>&1

# CentOS
if [ -r "/etc/centos-release" ]; then
  DIST_NAME="centos"
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
# Fedora
elif [ -r "/etc/fedora-release" ]; then
    DIST_NAME="fedora"
    DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/fedora-release`
# RedHat
elif [ -r "/etc/redhat-release" ]; then
  if grep -q "CentOS" /etc/redhat-release; then
      DIST_NAME="centos"
  else
      DIST_NAME="rhel"
  fi
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
# SUSE
elif [ -r "/etc/SuSE-release" ]; then
  if grep -q "openSUSE" /etc/SuSE-release; then
      DIST_NAME="generic"
      DIST_VER=""
  else
      DIST_NAME="sles"
      DIST_VER=`sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
  fi
elif [ -r "/etc/os-release" ]; then
  . /etc/os-release
  DIST_NAME=$ID
  DIST_VER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
  if [ "X$DIST_VER" = "X" ]; then
      DIST_VER="0"
  fi
  if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" != "2" ]; then
      DIST_VER="1"
  fi
  DIST_SUBVER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
  if [ "X$DIST_SUBVER" = "X" ]; then
      DIST_SUBVER="0"
  fi
else
  DIST_NAME="generic"
  DIST_VER=""
fi

# Add the SELinux policy
if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
  if [ $(getenforce) != "Disabled" ]; then
    semodule -i %{_localstatedir}/var/selinux/wazuh.pp
    semodule -e wazuh
  fi
fi

# Delete the installation files used to configure the local
rm -rf %{_localstatedir}/packages_files

# Remove unnecessary files from default group
rm -f %{_localstatedir}/etc/shared/default/*.rpmnew

# Remove old ossec user and group if exists and change ownwership of files

if getent group ossec > /dev/null 2>&1; then
  find %{_localstatedir}/ -group ossec -user root -exec chown root:test {} \; > /dev/null 2>&1 || true
  if getent passwd ossec > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossec -exec chown test:test {} \; > /dev/null 2>&1 || true
    userdel ossec > /dev/null 2>&1
  fi
  if getent passwd ossecm > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossecm -exec chown test:test {} \; > /dev/null 2>&1 || true
    userdel ossecm > /dev/null 2>&1
  fi
  if getent passwd ossecr > /dev/null 2>&1; then
    find %{_localstatedir}/ -group ossec -user ossecr -exec chown test:test {} \; > /dev/null 2>&1 || true
    userdel ossecr > /dev/null 2>&1
  fi
  if getent group ossec > /dev/null 2>&1; then
    groupdel ossec > /dev/null 2>&1
  fi
fi

%preun

if [ $1 = 0 ]; then

  # Stop the services before uninstall the package
  # Check for systemd
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-local > /dev/null 2>&1; then
    systemctl stop wazuh-local.service > /dev/null 2>&1
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-local status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-local stop > /dev/null 2>&1
  fi
  %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1

  # Remove the SELinux policy
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) != "Disabled" ]; then
      if (semodule -l | grep wazuh > /dev/null); then
        semodule -r wazuh > /dev/null
      fi
    fi
  fi

  # Remove SCA files
  rm -f %{_localstatedir}/ruleset/sca/*
fi

%postun

# If the package is been uninstalled
if [ $1 = 0 ];then
  # Remove the wazuh user if it exists
  if getent passwd wazuh > /dev/null 2>&1; then
    userdel wazuh >/dev/null 2>&1
  fi
  # Remove the wazuh group if it exists
  if command -v getent > /dev/null 2>&1 && getent group wazuh > /dev/null 2>&1; then
    groupdel wazuh >/dev/null 2>&1
  elif getent group wazuh > /dev/null 2>&1; then
    groupdel wazuh >/dev/null 2>&1
  fi

  # Backup agents centralized configuration (etc/shared)
  if [ -d %{_localstatedir}/etc/shared ]; then
      rm -rf %{_localstatedir}/etc/shared.save/
      mv %{_localstatedir}/etc/shared/ %{_localstatedir}/etc/shared.save/
  fi

  # Backup registration service certificates (ssllocal.cert,ssllocal.key)
  if [ -f %{_localstatedir}/etc/ssllocal.cert ]; then
      mv %{_localstatedir}/etc/ssllocal.cert %{_localstatedir}/etc/ssllocal.cert.save
  fi
  if [ -f %{_localstatedir}/etc/ssllocal.key ]; then
      mv %{_localstatedir}/etc/ssllocal.key %{_localstatedir}/etc/ssllocal.key.save
  fi

  # Remove lingering folders and files
  rm -rf %{_localstatedir}/queue/
  rm -rf %{_localstatedir}/framework/
  rm -rf %{_localstatedir}/api/
  rm -rf %{_localstatedir}/stats/
  rm -rf %{_localstatedir}/var/
  rm -rf %{_localstatedir}/bin/
  rm -rf %{_localstatedir}/logs/
  rm -rf %{_localstatedir}/ruleset/
  rm -rf %{_localstatedir}/tmp
fi

# posttrans code is the last thing executed in a install/upgrade
%posttrans

if [ -f %{_sysconfdir}/systemd/system/wazuh-local.service ]; then
  rm -rf %{_sysconfdir}/systemd/system/wazuh-local.service
  systemctl daemon-reload > /dev/null 2>&1
fi

if [ -f %{_localstatedir}/tmp/wazuh.restart ]; then
  rm -f %{_localstatedir}/tmp/wazuh.restart
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
    systemctl daemon-reload > /dev/null 2>&1
    systemctl restart wazuh-local.service > /dev/null 2>&1
  elif command -v service > /dev/null 2>&1 ; then
    service wazuh-local restart > /dev/null 2>&1
  else
    %{_localstatedir}/bin/wazuh-control restart > /dev/null 2>&1
  fi
fi

if [ -d %{_localstatedir}/logs/ossec ]; then
  rm -rf %{_localstatedir}/logs/ossec/
fi

if [ -d %{_localstatedir}/queue/ossec ]; then
  rm -rf %{_localstatedir}/queue/ossec/
fi

if [ -f %{_sysconfdir}/ossec-init.conf ]; then
  rm -f %{_sysconfdir}/ossec-init.conf
  rm -f %{_localstatedir}/etc/ossec-init.conf
fi

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/etc
 chown root:test %{_localstatedir}/etc/localtime
 chmod 0640 %{_localstatedir}/etc/localtime

%clean
rm -fr %{buildroot}

%files
%defattr(-,root, test)
%config(missingok) %{_init_scripts}/wazuh-local
%attr(640, root, test) %verify(not md5 size mtime) %ghost %{_sysconfdir}/ossec-init.conf
%dir %attr(750, root, test) %{_localstatedir}
%attr(750, root, test) %{_localstatedir}/agentless
%dir %attr(750, root, test) %{_localstatedir}/active-response
%dir %attr(750, root, test) %{_localstatedir}/active-response/bin
%attr(750, root, test) %{_localstatedir}/active-response/bin/*
%dir %attr(750, root, test) %{_localstatedir}/api
%dir %attr(770, root, test) %{_localstatedir}/api/configuration
%attr(660, root, test) %config(noreplace) %{_localstatedir}/api/configuration/api.yaml
%dir %attr(770, root, test) %{_localstatedir}/api/configuration/security
%dir %attr(770, root, test) %{_localstatedir}/api/configuration/ssl
%dir %attr(750, root, test) %{_localstatedir}/api/scripts
%attr(640, root, test) %{_localstatedir}/api/scripts/wazuh-apid.py
%dir %attr(750, root, test) %{_localstatedir}/backup
%dir %attr(750, test, test) %{_localstatedir}/backup/agents
%dir %attr(750, test, test) %{_localstatedir}/backup/groups
%dir %attr(750, root, test) %{_localstatedir}/backup/shared
%dir %attr(750, root, test) %{_localstatedir}/bin
%attr(750, root, root) %{_localstatedir}/bin/agent_control
%attr(750, root, test) %{_localstatedir}/bin/agent_groups
%attr(750, root, test) %{_localstatedir}/bin/agent_upgrade
%attr(750, root, root) %{_localstatedir}/bin/clear_stats
%attr(750, root, test) %{_localstatedir}/bin/cluster_control
%attr(750, root, root) %{_localstatedir}/bin/manage_agents
%attr(750, root, root) %{_localstatedir}/bin/wazuh-agentlessd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-analysisd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-authd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-control
%attr(750, root, root) %{_localstatedir}/bin/wazuh-csyslogd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-dbd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-execd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-integratord
%attr(750, root, root) %{_localstatedir}/bin/wazuh-logcollector
%attr(750, root, root) %{_localstatedir}/bin/wazuh-logtest-legacy
%attr(750, root, test) %{_localstatedir}/bin/wazuh-logtest
%attr(750, root, root) %{_localstatedir}/bin/wazuh-maild
%attr(750, root, root) %{_localstatedir}/bin/wazuh-monitord
%attr(750, root, root) %{_localstatedir}/bin/wazuh-regex
%attr(750, root, root) %{_localstatedir}/bin/wazuh-remoted
%attr(750, root, root) %{_localstatedir}/bin/wazuh-reportd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-syscheckd
%attr(750, root, test) %{_localstatedir}/bin/verify-agent-conf
%attr(750, root, test) %{_localstatedir}/bin/wazuh-apid
%attr(750, root, test) %{_localstatedir}/bin/wazuh-clusterd
%attr(750, root, root) %{_localstatedir}/bin/wazuh-db
%attr(750, root, root) %{_localstatedir}/bin/wazuh-modulesd
%dir %attr(770, test, test) %{_localstatedir}/etc
%attr(660, root, test) %config(noreplace) %{_localstatedir}/etc/ossec.conf
%attr(640, root, test) %config(noreplace) %{_localstatedir}/etc/client.keys
%attr(640, root, test) %{_localstatedir}/etc/internal_options*
%attr(640, root, test) %config(noreplace) %{_localstatedir}/etc/local_internal_options.conf
%attr(640, root, test) %{_localstatedir}/etc/localtime
%dir %attr(770, root, test) %{_localstatedir}/etc/decoders
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/decoders/local_decoder.xml
%dir %attr(770, root, test) %{_localstatedir}/etc/lists
%dir %attr(770, test, test) %{_localstatedir}/etc/lists/amazon
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/lists/amazon/*
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/lists/audit-keys
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/lists/security-eventchannel
%dir %attr(770, root, test) %{_localstatedir}/etc/shared
%dir %attr(770, test, test) %{_localstatedir}/etc/shared/default
%attr(660, test, test) %{_localstatedir}/etc/shared/agent-template.conf
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/shared/default/*
%dir %attr(770, root, test) %{_localstatedir}/etc/rootcheck
%attr(660, root, test) %{_localstatedir}/etc/rootcheck/*.txt
%dir %attr(770, root, test) %{_localstatedir}/etc/rules
%attr(660, test, test) %config(noreplace) %{_localstatedir}/etc/rules/local_rules.xml
%dir %attr(750, root, test) %{_localstatedir}/framework
%dir %attr(750, root, test) %{_localstatedir}/framework/python
%{_localstatedir}/framework/python/*
%dir %attr(750, root, test) %{_localstatedir}/framework/scripts
%attr(640, root, test) %{_localstatedir}/framework/scripts/*.py
%dir %attr(750, root, test) %{_localstatedir}/framework/wazuh
%attr(640, root, test) %{_localstatedir}/framework/wazuh/*.py
%dir %attr(750, root, test) %{_localstatedir}/framework/wazuh/core/cluster
%attr(640, root, test) %{_localstatedir}/framework/wazuh/core/cluster/*.py
%attr(640, root, test) %{_localstatedir}/framework/wazuh/core/cluster/*.json
%dir %attr(750, root, test) %{_localstatedir}/framework/wazuh/core/cluster/dapi
%attr(640, root, test) %{_localstatedir}/framework/wazuh/core/cluster/dapi/*.py
%dir %attr(750, root, test) %{_localstatedir}/integrations
%attr(750, root, test) %{_localstatedir}/integrations/*
%dir %attr(750, root, test) %{_localstatedir}/lib
%attr(750, root, test) %{_localstatedir}/lib/libwazuhext.so
%attr(750, root, test) %{_localstatedir}/lib/libwazuhshared.so
%attr(750, root, test) %{_localstatedir}/lib/libdbsync.so
%attr(750, root, test) %{_localstatedir}/lib/librsync.so
%attr(750, root, test) %{_localstatedir}/lib/libsyscollector.so
%attr(750, root, test) %{_localstatedir}/lib/libsysinfo.so
%{_localstatedir}/lib/libpython3.9.so.1.0
%dir %attr(770, test, test) %{_localstatedir}/logs
%attr(660, test, test)  %ghost %{_localstatedir}/logs/active-responses.log
%attr(660, test, test) %ghost %{_localstatedir}/logs/api.log
%attr(640, test, test) %ghost %{_localstatedir}/logs/integrations.log
%attr(660, test, test) %ghost %{_localstatedir}/logs/ossec.log
%attr(660, test, test) %ghost %{_localstatedir}/logs/ossec.json
%dir %attr(750, test, test) %{_localstatedir}/logs/api
%dir %attr(750, test, test) %{_localstatedir}/logs/archives
%dir %attr(750, test, test) %{_localstatedir}/logs/alerts
%dir %attr(750, test, test) %{_localstatedir}/logs/cluster
%dir %attr(750, test, test) %{_localstatedir}/logs/firewall
%dir %attr(750, test, test) %{_localstatedir}/logs/wazuh
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/add_localfiles.sh
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/gen_ossec.sh
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/src/
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/src/REVISION
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/src/VERSION
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/src/init/
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/src/init/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/generic
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/generic/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/centos
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/centos/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/rhel
%attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/local_installation_scripts/etc/templates/config/rhel/*
%dir %attr(750, root, test) %{_localstatedir}/queue
%attr(600, root, test) %ghost %{_localstatedir}/queue/agents-timestamp
%dir %attr(770, root, test) %{_localstatedir}/queue/agent-groups
%dir %attr(750, test, test) %{_localstatedir}/queue/agentless
%dir %attr(770, test, test) %{_localstatedir}/queue/alerts
%dir %attr(770, test, test) %{_localstatedir}/queue/cluster
%dir %attr(750, test, test) %{_localstatedir}/queue/db
%dir %attr(750, test, test) %{_localstatedir}/queue/diff
%dir %attr(750, test, test) %{_localstatedir}/queue/fim
%dir %attr(750, test, test) %{_localstatedir}/queue/fim/db
%dir %attr(750, test, test) %{_localstatedir}/queue/syscollector
%dir %attr(750, test, test) %{_localstatedir}/queue/syscollector/db
%attr(640, root, test) %{_localstatedir}/queue/syscollector/norm_config.json
%dir %attr(750, test, test) %{_localstatedir}/queue/fts
%dir %attr(770, test, test) %{_localstatedir}/queue/rids
%dir %attr(770, test, test) %{_localstatedir}/queue/tasks
%dir %attr(770, test, test) %{_localstatedir}/queue/sockets
%dir %attr(660, root, test) %{_localstatedir}/queue/vulnerabilities
%dir %attr(440, root, test) %{_localstatedir}/queue/vulnerabilities/dictionaries
%dir %attr(750, test, test) %{_localstatedir}/queue/logcollector
%attr(0440, root, test) %{_localstatedir}/queue/vulnerabilities/dictionaries/cpe_helper.json
%attr(0440, root, test) %ghost %{_localstatedir}/queue/vulnerabilities/dictionaries/msu.json.gz
%dir %attr(750, root, test) %{_localstatedir}/ruleset
%dir %attr(750, root, test) %{_localstatedir}/ruleset/sca
%dir %attr(750, root, test) %{_localstatedir}/ruleset/decoders
%attr(640, root, test) %{_localstatedir}/ruleset/decoders/*
%dir %attr(750, root, test) %{_localstatedir}/ruleset/rules
%attr(640, root, test) %{_localstatedir}/ruleset/rules/*
%dir %attr(770, root, test) %{_localstatedir}/.ssh
%dir %attr(750, test, test) %{_localstatedir}/stats
%dir %attr(1770, root, test) %{_localstatedir}/tmp
%dir %attr(750, root, test) %{_localstatedir}/var
%dir %attr(770, root, test) %{_localstatedir}/var/db
%dir %attr(770, root, test) %{_localstatedir}/var/db/agents
%attr(660, root, test) %{_localstatedir}/var/db/mitre.db
%dir %attr(770, root, test) %{_localstatedir}/var/download
%dir %attr(770, test, test) %{_localstatedir}/var/multigroups
%dir %attr(770, root, test) %{_localstatedir}/var/run
%dir %attr(770, root, test) %{_localstatedir}/var/selinux
%attr(640, root, test) %{_localstatedir}/var/selinux/*
%dir %attr(770, root, test) %{_localstatedir}/var/upgrade
%dir %attr(770, root, test) %{_localstatedir}/var/wodles
%dir %attr(750, root, test) %{_localstatedir}/wodles
%attr(750,root, test) %{_localstatedir}/wodles/*
%dir %attr(750, root, test) %{_localstatedir}/wodles/aws
%attr(750, root, test) %{_localstatedir}/wodles/aws/*
%dir %attr(750, root, test) %{_localstatedir}/wodles/azure
%attr(750, root, test) %{_localstatedir}/wodles/azure/*
%dir %attr(750, root, test) %{_localstatedir}/wodles/docker
%attr(750, root, test) %{_localstatedir}/wodles/docker/*
%dir %attr(750, root, test) %{_localstatedir}/wodles/gcloud
%attr(750, root, test) %{_localstatedir}/wodles/gcloud/*

%changelog
* Thu Nov 10 2022 support <info@wazuh.com> - 4.3.10
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Oct 03 2022 support <info@wazuh.com> - 4.3.9
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Sep 21 2022 support <info@wazuh.com> - 3.13.6
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Sep 19 2022 support <info@wazuh.com> - 4.3.8
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Aug 24 2022 support <info@wazuh.com> - 3.13.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Aug 08 2022 support <info@wazuh.com> - 4.3.7
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Jul 07 2022 support <info@wazuh.com> - 4.3.6
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jun 29 2022 support <info@wazuh.com> - 4.3.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jun 07 2022 support <info@wazuh.com> - 4.3.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue May 31 2022 support <info@wazuh.com> - 4.3.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon May 30 2022 support <info@wazuh.com> - 4.3.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon May 30 2022 support <info@wazuh.com> - 3.13.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Sun May 29 2022 support <info@wazuh.com> - 4.2.7
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed May 18 2022 support <info@wazuh.com> - 4.3.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu May 05 2022 support <info@wazuh.com> - 4.3.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri Mar 25 2022 support <info@wazuh.com> - 4.2.6
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 15 2021 support <info@wazuh.com> - 4.2.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Oct 21 2021 support <info@wazuh.com> - 4.2.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Oct 06 2021 support <info@wazuh.com> - 4.2.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Sep 28 2021 support <info@wazuh.com> - 4.2.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Sat Sep 25 2021 support <info@wazuh.com> - 4.2.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Apr 26 2021 support <info@wazuh.com> - 4.2.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Sat Apr 24 2021 support <info@wazuh.com> - 3.13.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Apr 22 2021 support <info@wazuh.com> - 4.1.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Mar 29 2021 support <info@wazuh.com> - 4.1.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Sat Mar 20 2021 support <info@wazuh.com> - 4.1.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Mar 08 2021 support <info@wazuh.com> - 4.1.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri Mar 05 2021 support <info@wazuh.com> - 4.1.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jan 19 2021 support <info@wazuh.com> - 4.1.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jan 12 2021 support <info@wazuh.com> - 4.0.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 30 2020 support <info@wazuh.com> - 4.0.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 23 2020 support <info@wazuh.com> - 4.0.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Sat Oct 31 2020 support <info@wazuh.com> - 4.0.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Oct 19 2020 support <info@wazuh.com> - 4.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri Aug 21 2020 support <info@wazuh.com> - 3.13.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jul 14 2020 support <info@wazuh.com> - 3.13.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jun 29 2020 support <info@wazuh.com> - 3.13.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed May 13 2020 support <info@wazuh.com> - 3.12.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Apr 9 2020 support <info@wazuh.com> - 3.12.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Apr 8 2020 support <info@wazuh.com> - 3.12.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Mar 25 2020 support <info@wazuh.com> - 3.12.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Feb 24 2020 support <info@wazuh.com> - 3.11.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jan 22 2020 support <info@wazuh.com> - 3.11.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jan 7 2020 support <info@wazuh.com> - 3.11.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Dec 26 2019 support <info@wazuh.com> - 3.11.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Oct 7 2019 support <info@wazuh.com> - 3.11.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Sep 23 2019 support <info@wazuh.com> - 3.10.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Sep 19 2019 support <info@wazuh.com> - 3.10.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Aug 26 2019 support <info@wazuh.com> - 3.10.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Aug 8 2019 support <info@wazuh.com> - 3.9.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri Jul 12 2019 support <info@wazuh.com> - 3.9.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jun 11 2019 support <info@wazuh.com> - 3.9.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Jun 6 2019 support <info@wazuh.com> - 3.9.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon May 6 2019 support <info@wazuh.com> - 3.9.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Feb 25 2019 support <info@wazuh.com> - 3.9.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jan 30 2019 support <info@wazuh.com> - 3.8.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Jan 24 2019 support <info@wazuh.com> - 3.8.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jan 16 2019 support <info@wazuh.com> - 3.8.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Dec 10 2018 support <info@wazuh.com> - 3.7.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 12 2018 support <info@wazuh.com> - 3.7.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Sat Nov 10 2018 support <info@wazuh.com> - 3.7.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Sep 3 2018 support <info@wazuh.com> - 3.6.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Aug 23 2018 support <support@wazuh.com> - 3.6.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jul 25 2018 support <support@wazuh.com> - 3.5.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jul 11 2018 support <support@wazuh.com> - 3.4.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jun 18 2018 support <support@wazuh.com> - 3.3.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jun 11 2018 support <support@wazuh.com> - 3.3.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed May 30 2018 support <support@wazuh.com> - 3.2.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu May 10 2018 support <support@wazuh.com> - 3.2.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Apr 09 2018 support <support@wazuh.com> - 3.2.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Feb 21 2018 support <support@wazuh.com> - 3.2.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Feb 07 2018 support <support@wazuh.com> - 3.2.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Dec 19 2017 support <support@wazuh.com> - 3.1.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 06 2017 support <support@wazuh.com> - 3.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jun 06 2017 support <support@wazuh.com> - 2.0.1
- Changed random data generator for a secure OS-provided generator.
- Changed Windows installer file name (depending on version).
- Linux distro detection using standard os-release file.
- Changed some URLs to documentation.
- Disable synchronization with SQLite databases for Syscheck by default.
- Minor changes at Rootcheck formatter for JSON alerts.
- Added debugging messages to Integrator logs.
- Show agent ID when possible on logs about incorrectly formatted messages.
- Use default maximum inotify event queue size.
- Show remote IP on encoding format errors when unencrypting messages.
- Fix permissions in agent-info folder
- Fix permissions in rids folder.
* Fri Apr 21 2017 Jose Luis Ruiz <jose@wazuh.com> - 2.0
- Changed random data generator for a secure OS-provided generator.
- Changed Windows installer file name (depending on version).
- Linux distro detection using standard os-release file.
- Changed some URLs to documentation.
- Disable synchronization with SQLite databases for Syscheck by default.
- Minor changes at Rootcheck formatter for JSON alerts.
- Added debugging messages to Integrator logs.
- Show agent ID when possible on logs about incorrectly formatted messages.
- Use default maximum inotify event queue size.
- Show remote IP on encoding format errors when unencrypting messages.
- Fixed resource leaks at rules configuration parsing.
- Fixed memory leaks at rules parser.
- Fixed memory leaks at XML decoders parser.
- Fixed TOCTOU condition when removing directories recursively.
- Fixed insecure temporary file creation for old POSIX specifications.
- Fixed missing agentless devices identification at JSON alerts.
- Fixed FIM timestamp and file name issue at SQLite database.
- Fixed cryptographic context acquirement on Windows agents.
- Fixed debug mode for Analysisd.
- Fixed bad exclusion of BTRFS filesystem by Rootcheck.
- Fixed compile errors on macOS.
- Fixed option -V for Integrator.
- Exclude symbolic links to directories when sending FIM diffs (by Stephan Joerrens).
- Fixed daemon list for service reloading at ossec-control.
- Fixed socket waiting issue on Windows agents.
- Fixed PCI_DSS definitions grouping issue at Rootcheck controls.
