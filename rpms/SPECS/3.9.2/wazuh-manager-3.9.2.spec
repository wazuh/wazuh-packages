Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-manager
Version:     3.9.2
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(post):   /sbin/chkconfig
Requires(preun):  /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service /usr/sbin/groupdel /usr/sbin/userdel
Conflicts:   ossec-hids ossec-hids-agent wazuh-agent wazuh-local
AutoReqProv: no

Requires: coreutils
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils-python curl perl

ExclusiveOS: linux

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q

./gen_ossec.sh conf manager centos %rhel %{_localstatedir}/ossec > etc/ossec-server.conf
./gen_ossec.sh init manager %{_localstatedir}/ossec > ossec-init.conf

pushd src
# Rebuild for server
make clean

# Build Wazuh sources
make deps PREFIX=%{_localstatedir}/ossec
make -j%{_threads} TARGET=server USE_SELINUX=yes USE_FRAMEWORK_LIB=yes PREFIX=%{_localstatedir}/ossec DEBUG=%{_debugenabled}

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="server"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}/ossec"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ACTIVE_RESPONSE="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="y"' >> ./etc/preloaded-vars.conf
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

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh

# Copy the installed files into RPM_BUILD_ROOT directory
cp -pr %{_localstatedir}/ossec/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0755 src/init/ossec-hids-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-manager

# Install oscap files
install -m 0640 wodles/oscap/content/*redhat* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*rhel* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*centos* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*fedora* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/fedora
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/rhel

# Add SUSE initscript
cp -rp src/init/ossec-hids-suse.init ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init/

# Copy scap templates
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/generic
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/centos
cp -rp  etc/templates/config/fedora/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/fedora
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/rhel

install -m 0640 src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/
cp src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/
cp -r src/systemd/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd

exit 0
%pre

# Stop Authd if it is running
if ps aux | grep %{_localstatedir}/ossec/bin/ossec-authd | grep -v grep > /dev/null 2>&1; then
   kill `ps -ef | grep '%{_localstatedir}/ossec/bin/ossec-authd' | grep -v grep | awk '{print $2}'` > /dev/null 2>&1
fi

# Ensure that the wazuh-manager is stopped
if [ -d %{_localstatedir}/ossec ] && [ -f %{_localstatedir}/ossec/bin/ossec-control ] ; then
  %{_localstatedir}/ossec/bin/ossec-control stop > /dev/null 2>&1
fi

# Create the ossec group if it doesn't exists
if command -v getent > /dev/null 2>&1 && ! getent group ossec > /dev/null 2>&1; then
  groupadd -r ossec
elif ! id -g ossec > /dev/null 2>&1; then
  groupadd -r ossec
fi
# Create the ossec user if it doesn't exists
if ! id -u ossec > /dev/null 2>&1; then
  useradd -g ossec -G ossec -d %{_localstatedir}/ossec -r -s /sbin/nologin ossec
fi
# Create the ossecr user if it doesn't exists
if ! id -u ossecr > /dev/null 2>&1; then
  useradd -g ossec -G ossec -d %{_localstatedir}/ossec -r -s /sbin/nologin ossecr
fi
# Create the ossecm user if it doesn't exists
if ! id -u ossecm > /dev/null 2>&1; then
  useradd -g ossec -G ossec -d %{_localstatedir}/ossec -r -s /sbin/nologin ossecm
fi

if [ -d ${DIR}/var/db/agents ]; then
  rm -f ${DIR}/var/db/agents/*
fi

# Remove existing SQLite databases
rm -f %{_localstatedir}/ossec/var/db/global.db* || true
rm -f %{_localstatedir}/ossec/var/db/cluster.db* || true
rm -f %{_localstatedir}/ossec/var/db/.profile.db* || true
rm -f %{_localstatedir}/ossec/var/db/agents/* || true
# Remove Vuln-detector database
rm -f %{_localstatedir}/ossec/queue/vulnerabilities/cve.db || true


# Remove existing SQLite databases for Wazuh DB when upgrading
# Wazuh only if upgrading from 3.2..3.6
if [ $1 = 2 ]; then

  # Import the variables from ossec-init.conf file
  if [ -f %{_sysconfdir}/ossec-init.conf ]; then
    . %{_sysconfdir}/ossec-init.conf
  fi

  # Get the major and minor version
  MAJOR=$(echo $VERSION | cut -dv -f2 | cut -d. -f1)
  MINOR=$(echo $VERSION | cut -d. -f2)

  if [ $MAJOR = 3 ] && [ $MINOR -lt 7 ]; then
    rm -f %{_localstatedir}/ossec/queue/db/*.db*
    rm -f %{_localstatedir}/ossec/queue/db/.template.db
  fi
fi

# Delete old service
if [ -f /etc/init.d/ossec ]; then
  rm /etc/init.d/ossec
fi
# Execute this if only when installing the package
if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf ]; then
    echo "====================================================================================="
    echo "= Backup from your ossec.conf has been created at %{_localstatedir}/ossec/etc/ossec.conf.rpmorig ="
    echo "= Please verify your ossec.conf configuration at %{_localstatedir}/ossec/etc/ossec.conf          ="
    echo "====================================================================================="
    mv %{_localstatedir}/ossec/etc/ossec.conf %{_localstatedir}/ossec/etc/ossec.conf.rpmorig
  fi
fi
# Execute this if only when upgrading the package
if [ $1 = 2 ]; then
    cp -rp %{_localstatedir}/ossec/etc/ossec.conf %{_localstatedir}/ossec/etc/ossec.bck
    cp -rp %{_localstatedir}/ossec/etc/shared %{_localstatedir}/ossec/backup/
    if [ ! -d %{_localstatedir}/ossec/etc/shared/default ]; then
      mkdir  %{_localstatedir}/ossec/etc/shared/default
      cp -rp %{_localstatedir}/ossec/backup/shared/* %{_localstatedir}/ossec/etc/shared/default || true
      rm -f  %{_localstatedir}/ossec/etc/shared/merged.mg || true
      rm -f  %{_localstatedir}/ossec/etc/shared/default/ar.conf || true
    fi
fi
%post

# If the package is being installed
if [ $1 = 1 ]; then
  . %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init/dist-detect.sh

  sles=""
  if [ -f /etc/os-release ]; then
    if `grep -q "\"sles" /etc/os-release` ; then
      sles="suse"
    elif `grep -q -i "\"opensuse" /etc/os-release` ; then
      sles="opensuse"
    fi
  elif [ -f /etc/SuSE-release ]; then
    if `grep -q "SUSE Linux Enterprise Server" /etc/SuSE-release` ; then
      sles="suse"
    elif `grep -q -i "opensuse" /etc/SuSE-release` ; then
      sles="opensuse"
    fi
  fi
  if [ ! -z "$sles" ]; then
    install -m 755 %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init/ossec-hids-suse.init /etc/init.d/wazuh-manager
  fi

  # Generating ossec.conf file
  %{_localstatedir}/ossec/packages_files/manager_installation_scripts/gen_ossec.sh conf manager ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir}/ossec > %{_localstatedir}/ossec/etc/ossec.conf
  chown root:ossec %{_localstatedir}/ossec/etc/ossec.conf
  chmod 0640 %{_localstatedir}/ossec/etc/ossec.conf

  ETC_DECODERS="%{_localstatedir}/ossec/etc/decoders"
  ETC_RULES="%{_localstatedir}/ossec/etc/rules"

  # Moving local_decoder
  if [ -f "%{_localstatedir}/ossec/etc/local_decoder.xml" ]; then
    if [ -s "%{_localstatedir}/ossec/etc/local_decoder.xml" ]; then
      mv "%{_localstatedir}/ossec/etc/local_decoder.xml" $ETC_DECODERS
    else
      # it is empty
      rm -f "%{_localstatedir}/ossec/etc/local_decoder.xml"
    fi
  fi

  # Moving local_rules
  if [ -f "%{_localstatedir}/ossec/rules/local_rules.xml" ]; then
    mv "%{_localstatedir}/ossec/rules/local_rules.xml" $ETC_RULES
  fi

  # Creating backup directory
  if [ -d "%{_localstatedir}/ossec/etc/wazuh_decoders" ]; then
    BACKUP_RULESET="%{_localstatedir}/ossec/etc/backup_ruleset"
    mkdir $BACKUP_RULESET > /dev/null 2>&1
    chmod 750 $BACKUP_RULESET > /dev/null 2>&1
    chown root:ossec $BACKUP_RULESET > /dev/null 2>&1
    # Backup decoders: Wazuh v1.0.1 to v1.1.1
    old_decoders="ossec_decoders wazuh_decoders"
    for old_decoder in $old_decoders
    do
      if [ -d "%{_localstatedir}/ossec/etc/$old_decoder" ]; then
        mv "%{_localstatedir}/ossec/etc/$old_decoder" $BACKUP_RULESET
      fi
    done

    # Backup decoders: Wazuh v1.0 and OSSEC
    if [ -f "%{_localstatedir}/ossec/etc/decoder.xml" ]; then
      mv "%{_localstatedir}/ossec/etc/decoder.xml" $BACKUP_RULESET
    fi
    if [ -d "%{_localstatedir}/ossec/rules" ]; then
      # Backup rules: All versions
      mv "%{_localstatedir}/ossec/rules" $BACKUP_RULESET
    fi
  fi
  passlist="%{_localstatedir}/ossec/agentless/.passlist"

  if [ -f $passlist ] && ! base64 -d $passlist > /dev/null 2>&1; then
    cp $passlist $passlist.bak
    base64 $passlist.bak > $passlist

    if [ $? = 0 ]; then
      rm -f $passlist.bak
    else
      echo "ERROR: Couldn't encode Agentless passlist."
      mv $passlist.bak $passlist
    fi
  fi

  touch %{_localstatedir}/ossec/logs/active-responses.log
  touch %{_localstatedir}/ossec/logs/integrations.log
  chown ossec:ossec %{_localstatedir}/ossec/logs/active-responses.log
  chown ossecm:ossec %{_localstatedir}/ossec/logs/integrations.log
  chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log
  chmod 0640 %{_localstatedir}/ossec/logs/integrations.log

  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/packages_files/manager_installation_scripts/add_localfiles.sh %{_localstatedir}/ossec >> %{_localstatedir}/ossec/etc/ossec.conf
   /sbin/chkconfig --add wazuh-manager
   /sbin/chkconfig wazuh-manager on

  # If systemd is installed, add the wazuh-manager.service file to systemd files directory
  if [ -d /run/systemd/system ]; then

    # Fix for RHEL 8
    # Service must be installed in /usr/lib/systemd/system/
    if [ "${DIST_NAME}" == "rhel" -a "${DIST_VER}" == "8" ]; then
      install -m 644 %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd/wazuh-manager.service /usr/lib/systemd/system/
    else
      install -m 644 %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd/wazuh-manager.service /etc/systemd/system/
    fi

    # Fix for Fedora 28
    # Check if SELinux is installed. If it is installed, restore the context of the .service file
    if [ "${DIST_NAME}" == "fedora" -a "${DIST_VER}" == "28" ]; then
      if command -v restorecon > /dev/null 2>&1 ; then
        restorecon -v /etc/systemd/system/wazuh-manager.service > /dev/null 2>&1
      fi
    fi
    systemctl daemon-reload
    systemctl stop wazuh-manager
    systemctl enable wazuh-manager > /dev/null 2>&1
  fi

fi

if [ -f "%{_localstatedir}/ossec/etc/shared/agent.conf" ]; then
mv "%{_localstatedir}/ossec/etc/shared/agent.conf" "%{_localstatedir}/ossec/etc/shared/default/agent.conf"
chmod 0660 %{_localstatedir}/ossec/etc/shared/default/agent.conf
chown ossec:ossec %{_localstatedir}/ossec/etc/shared/default/agent.conf
fi

# Generation auto-signed certificate if not exists
if type openssl >/dev/null 2>&1 && [ ! -f "%{_localstatedir}/ossec/etc/sslmanager.key" ] && [ ! -f "%{_localstatedir}/ossec/etc/sslmanager.cert" ]; then
  openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout %{_localstatedir}/ossec/etc/sslmanager.key -out %{_localstatedir}/ossec/etc/sslmanager.cert
  chmod 640 %{_localstatedir}/ossec/etc/sslmanager.key
  chmod 640 %{_localstatedir}/ossec/etc/sslmanager.cert
fi

rm %{_localstatedir}/ossec/etc/shared/ar.conf  >/dev/null 2>&1 || true
rm %{_localstatedir}/ossec/etc/shared/merged.mg  >/dev/null 2>&1 || true

if [ $1 = 2 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.bck ]; then
      mv %{_localstatedir}/ossec/etc/ossec.bck %{_localstatedir}/ossec/etc/ossec.conf
  fi
fi

# Agent info change between 2.1.1 and 3.0.0
chmod 0660 %{_localstatedir}/ossec/queue/agent-info/* 2>/dev/null || true
chown ossecr:ossec %{_localstatedir}/ossec/queue/agent-info/* 2>/dev/null || true

# CentOS
if [ -r "/etc/centos-release" ]; then
  DIST_NAME="centos"
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
# RedHat
elif [ -r "/etc/redhat-release" ]; then
  if grep -q "CentOS" /etc/redhat-release; then
      DIST_NAME="centos"
  else
      DIST_NAME="rhel"
  fi
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
fi

# Add the SELinux policy
if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
  if [ $(getenforce) != "Disabled" ]; then
    semodule -i %{_localstatedir}/ossec/var/selinux/wazuh.pp
    semodule -e wazuh
  fi
fi

# Fix duplicated ID issue error
RULES_DIR=%{_localstatedir}/ossec/ruleset/rules
OLD_RULES="${RULES_DIR}/0520-vulnerability-detector.xml ${RULES_DIR}/0565-ms_ipsec_rules_json.xml"

for rules_file in ${OLD_RULES}; do
  if [ -f ${rules_file} ]; then
    mv ${rules_file} ${rules_file}.old
  fi
done

# Delete the installation files used to configure the manager
rm -rf %{_localstatedir}/ossec/packages_files

# Remove unnecessary files from default group
rm -f %{_localstatedir}/ossec/etc/shared/default/*.rpmnew

if %{_localstatedir}/ossec/bin/ossec-logtest 2>/dev/null ; then
  /sbin/service wazuh-manager restart > /dev/null 2>&1
else
  echo "================================================================================================================"
  echo "Something in your actual rules configuration is wrong, please review your configuration and restart the service."
  echo "================================================================================================================"
fi

# Restore the old files
for rules_file in ${OLD_RULES}; do
  if [ -f ${rules_file}.old ]; then
    mv ${rules_file}.old ${rules_file}
  fi
done

%preun

if [ $1 = 0 ]; then

  /sbin/service wazuh-manager stop > /dev/null 2>&1 || :
  %{_localstatedir}/ossec/bin/ossec-control stop > /dev/null 2>&1
  /sbin/chkconfig wazuh-manager off > /dev/null 2>&1
  /sbin/chkconfig --del wazuh-manager

  /sbin/service wazuh-manager stop > /dev/null 2>&1 || :

  # Remove the SELinux policy
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) != "Disabled" ]; then
      if (semodule -l | grep wazuh > /dev/null); then
        semodule -r wazuh > /dev/null
      fi
    fi
  fi

  # Remove the service file for SUSE hosts
  if [ -f /etc/os-release ]; then
    sles=$(grep "\"sles" /etc/os-release)
  elif [ -f /etc/SuSE-release ]; then
    sles=$(grep "SUSE Linux Enterprise Server" /etc/SuSE-release)
  fi
  if [ ! -z "$sles" ]; then
    rm -f /etc/init.d/wazuh-manager
  fi

  # Remove the service files
  # RHEL 8 service located in /usr/lib/systemd/system/
  if [ -f /usr/lib/systemd/system/wazuh-manager.service ]; then
    rm -f /usr/lib/systemd/system/wazuh-manager.service
  else
    rm -f /etc/systemd/system/wazuh-manager.service
  fi

fi

%postun

# If the package is been uninstalled
if [ $1 == 0 ];then
  # Remove the ossecr user if it exists
  if id -u ossecr > /dev/null 2>&1; then
    userdel ossecr >/dev/null 2>&1
  fi
  # Remove the ossecm user if it exists
  if id -u ossecm > /dev/null 2>&1; then
    userdel ossecm >/dev/null 2>&1
  fi
  # Remove the ossec user if it exists
  if id -u ossec > /dev/null 2>&1; then
    userdel ossec >/dev/null 2>&1
  fi
  # Remove the ossec group if it exists
  if command -v getent > /dev/null 2>&1 && getent group ossec > /dev/null 2>&1; then
    groupdel ossec >/dev/null 2>&1
  elif id -g ossec > /dev/null 2>&1; then
    groupdel ossec >/dev/null 2>&1
  fi

  # Backup agents centralized configuration (etc/shared)
  if [ -d %{_localstatedir}/ossec/etc/shared ]; then
      rm -rf %{_localstatedir}/ossec/etc/shared.save/
      mv %{_localstatedir}/ossec/etc/shared/ %{_localstatedir}/ossec/etc/shared.save/
  fi

  # Backup registration service certificates (sslmanager.cert,sslmanager.key)
  if [ -f %{_localstatedir}/ossec/etc/sslmanager.cert ]; then
      mv %{_localstatedir}/ossec/etc/sslmanager.cert %{_localstatedir}/ossec/etc/sslmanager.cert.save
  fi
  if [ -f %{_localstatedir}/ossec/etc/sslmanager.key ]; then
      mv %{_localstatedir}/ossec/etc/sslmanager.key %{_localstatedir}/ossec/etc/sslmanager.key.save
  fi

  # Remove lingering folders and files
  rm -rf %{_localstatedir}/ossec/queue/
  rm -rf %{_localstatedir}/ossec/framework/
  rm -rf %{_localstatedir}/ossec/stats/
  rm -rf %{_localstatedir}/ossec/var/
  rm -rf %{_localstatedir}/ossec/bin/
  rm -rf %{_localstatedir}/ossec/logs/

fi

# If the package is been downgraded
if [ $1 == 1 ]; then
  # Load the ossec-init.conf file to get the current version
  . /etc/ossec-init.conf

  # Get the major and minor version
  MAJOR=$(echo $VERSION | cut -dv -f2 | cut -d. -f1)
  MINOR=$(echo $VERSION | cut -d. -f2)

  # Restore the configuration files from the .rpmsave file
  if [ $MAJOR = 3 ] && [ $MINOR -lt 7 ]; then
    # Restore client.keys file
    if [ -f %{_localstatedir}/ossec/etc/client.keys.rpmsave ]; then
      mv %{_localstatedir}/ossec/etc/client.keys.rpmsave %{_localstatedir}/ossec/etc/client.keys
      chmod 640 %{_localstatedir}/ossec/etc/client.keys
      chown root:ossec %{_localstatedir}/ossec/etc/client.keys
    fi
    # Restore the ossec.conf file
    if [ -f %{_localstatedir}/ossec/etc/ossec.conf.rpmsave ]; then
      mv %{_localstatedir}/ossec/etc/ossec.conf.rpmsave %{_localstatedir}/ossec/etc/ossec.conf
      chmod 640 %{_localstatedir}/ossec/etc/ossec.conf
      chown root:ossec %{_localstatedir}/ossec/etc/ossec.conf
    fi
    # Restart the manager
    if %{_localstatedir}/ossec/bin/ossec-logtest 2>/dev/null ; then
      /sbin/service wazuh-manager restart > /dev/null 2>&1
    fi
  fi
fi

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/ossec/etc
 chown root:ossec %{_localstatedir}/ossec/etc/localtime
 chmod 0640 %{_localstatedir}/ossec/etc/localtime

%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%attr(640, root, ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%dir %attr(750, root, ossec) %{_localstatedir}/ossec
%attr(750, root, ossec) %{_localstatedir}/ossec/agentless
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/active-response
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/active-response/bin
%attr(750, root, ossec) %{_localstatedir}/ossec/active-response/bin/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/backup
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/backup/agents
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/backup/groups
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/backup/shared
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/bin
%attr(750, root, root) %{_localstatedir}/ossec/bin/agent_control
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/agent_groups
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/agent_upgrade
%attr(750, root, root) %{_localstatedir}/ossec/bin/clear_stats
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/cluster_control
%attr(750, root, root) %{_localstatedir}/ossec/bin/manage_agents
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-agentlessd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-analysisd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-authd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-control
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-csyslogd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-dbd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-execd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-integratord
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-logcollector
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-logtest
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-maild
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-makelists
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-monitord
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-regex
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-remoted
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-reportd
%attr(750, root, root) %{_localstatedir}/ossec/bin/ossec-syscheckd
%attr(750, root, root) %{_localstatedir}/ossec/bin/rootcheck_control
%attr(750, root, root) %{_localstatedir}/ossec/bin/syscheck_control
%attr(750, root, root) %{_localstatedir}/ossec/bin/syscheck_update
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/update_ruleset
%attr(750, root, root) %{_localstatedir}/ossec/bin/util.sh
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/verify-agent-conf
%attr(750, root, ossec) %{_localstatedir}/ossec/bin/wazuh-clusterd
%attr(750, root, root) %{_localstatedir}/ossec/bin/wazuh-db
%attr(750, root, root) %{_localstatedir}/ossec/bin/wazuh-modulesd
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/etc
%attr(640, root, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/ossec.conf
%attr(640, root, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/client.keys
%attr(640, root, ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640, root, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/local_internal_options.conf
%{_localstatedir}/ossec/etc/ossec-init.conf
%attr(640, root, ossec) %{_localstatedir}/ossec/etc/localtime
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/etc/decoders
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/decoders/local_decoder.xml
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/etc/lists
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/etc/lists/amazon
%attr(660, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/amazon/*
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/audit-keys
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/audit-keys.cdb
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/security-eventchannel
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/security-eventchannel.cdb
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/etc/shared
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/etc/shared/default
%attr(660, ossec, ossec) %{_localstatedir}/ossec/etc/shared/agent-template.conf
%attr(660, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/shared/default/*
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/etc/rootcheck
%attr(660, root, ossec) %{_localstatedir}/ossec/etc/rootcheck/*.txt
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/etc/rules
%attr(640, ossec, ossec) %config(noreplace) %{_localstatedir}/ossec/etc/rules/local_rules.xml
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework/lib
%attr(750, root, ossec) %{_localstatedir}/ossec/framework/lib/libsqlite3.so.0
%{_localstatedir}/ossec/framework/python/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework/scripts
%attr(640, root, ossec) %{_localstatedir}/ossec/framework/scripts/*.py
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework/wazuh
%attr(640, root, ossec) %{_localstatedir}/ossec/framework/wazuh/*.py
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework/wazuh/cluster
%attr(640, root, ossec) %{_localstatedir}/ossec/framework/wazuh/cluster/*.py
%attr(640, root, ossec) %{_localstatedir}/ossec/framework/wazuh/cluster/*.json
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/framework/wazuh/cluster/dapi
%attr(640, root, ossec) %{_localstatedir}/ossec/framework/wazuh/cluster/dapi/*.py
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/integrations
%attr(750, root, ossec) %{_localstatedir}/ossec/integrations/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/lib
%attr(750, root, ossec) %{_localstatedir}/ossec/lib/libwazuhext.so
%{_localstatedir}/ossec/lib/libpython3.7m.so.1.0
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/logs
%attr(660, ossec, ossec)  %ghost %{_localstatedir}/ossec/logs/active-responses.log
%attr(640, ossecm, ossec) %ghost %{_localstatedir}/ossec/logs/integrations.log
%attr(660, ossec, ossec) %ghost %{_localstatedir}/ossec/logs/ossec.log
%attr(660, ossec, ossec) %ghost %{_localstatedir}/ossec/logs/ossec.json
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/archives
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/alerts
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/cluster
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/firewall
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/ossec
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/add_localfiles.sh
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/gen_ossec.sh
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/LOCATION
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/REVISION
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/VERSION
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init/
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/init/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd/
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/src/systemd/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/generic
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/generic/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/centos
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/centos/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/fedora
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/fedora/*
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/rhel
%attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/manager_installation_scripts/etc/templates/config/rhel/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/queue
%attr(600, root, ossec) %ghost %{_localstatedir}/ossec/queue/agents-timestamp
%dir %attr(770, ossecr, ossec) %{_localstatedir}/ossec/queue/agent-info
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/queue/agent-groups
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/queue/agentless
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/queue/alerts
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/queue/cluster
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/queue/db
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/queue/diff
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/queue/fts
%dir %attr(770, ossecr, ossec) %{_localstatedir}/ossec/queue/rids
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/queue/rootcheck
%dir %attr(770, ossec, ossec) %{_localstatedir}/ossec/queue/ossec
%dir %attr(760, root, ossec) %{_localstatedir}/ossec/queue/vulnerabilities
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset/sca
%attr(640, root, ossec) %{_localstatedir}/ossec/ruleset/sca/*
%attr(640, root, ossec) %{_localstatedir}/ossec/ruleset/VERSION
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset/decoders
%attr(640, root, ossec) %{_localstatedir}/ossec/ruleset/decoders/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset/rules
%attr(640, root, ossec) %{_localstatedir}/ossec/ruleset/rules/*
%dir %attr(700, root, ossec) %{_localstatedir}/ossec/.ssh
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/stats
%dir %attr(1770, root, ossec) %{_localstatedir}/ossec/tmp
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/var
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/db
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/db/agents
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/download
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/multigroups
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/run
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/selinux
%attr(640, root, ossec) %{_localstatedir}/ossec/var/selinux/*
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/upgrade
%dir %attr(770, root, ossec) %{_localstatedir}/ossec/var/wodles
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles/aws
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/aws/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles/azure
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/azure/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles/docker
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/docker/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles/oscap
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/oscap/oscap
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/oscap/oscap.*
%attr(750, root, ossec) %{_localstatedir}/ossec/wodles/oscap/template*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/wodles/oscap/content
%attr(640, root, ossec) %{_localstatedir}/ossec/wodles/oscap/content/*

%{_initrddir}/*
%if %{_debugenabled} == "yes"
/usr/lib/debug/%{_localstatedir}/ossec/*
/usr/src/debug/%{name}-%{version}/*
%endif


%changelog
* Mon Jun 6 2019 support <info@wazuh.com> - 3.9.2
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
