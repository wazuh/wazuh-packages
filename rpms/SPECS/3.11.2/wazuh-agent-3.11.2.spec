Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-agent
Version:     3.11.2
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
Requires(postun): /sbin/service
Conflicts:   ossec-hids ossec-hids-agent wazuh-manager wazuh-local
AutoReqProv: no

Requires: coreutils
%if 0%{?el} >= 6 || 0%{?rhel} >= 6
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils-python perl
%else
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils perl
%endif

ExclusiveOS: linux

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q

echo "Vendor is %_vendor"

./gen_ossec.sh conf agent centos %rhel %{_localstatedir}/ossec > etc/ossec-agent.conf
./gen_ossec.sh init agent %{_localstatedir}/ossec > ossec-init.conf

%build
pushd src
# Rebuild for agent
make clean

%if 0%{?el} >= 6 || 0%{?rhel} >= 6
    make deps
    make -j%{_threads} TARGET=agent USE_SELINUX=yes PREFIX=%{_localstatedir}/ossec DEBUG=%{_debugenabled}
%else
    %ifnarch x86_64
      MSGPACK="USE_MSGPACK_OPT=no"
    %endif
    make deps RESOURCES_URL=http://packages.wazuh.com/deps/3.11
    make -j%{_threads} TARGET=agent USE_AUDIT=no USE_SELINUX=yes USE_EXEC_ENVIRON=no PREFIX=%{_localstatedir}/ossec DEBUG=%{_debugenabled} ${MSGPACK}

%endif

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="agent"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}/ossec"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ACTIVE_RESPONSE="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCOLLECTOR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_CISCAT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
echo 'USER_AGENT_SERVER_IP="MANAGER_IP"' >> ./etc/preloaded-vars.conf
echo 'USER_CA_STORE="/path/to/my_cert.pem"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf
./install.sh

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh

# Copy the installed files into RPM_BUILD_ROOT directory
cp -pr %{_localstatedir}/ossec/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0755 src/init/ossec-hids-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-agent

# Install oscap files
install -m 0640 wodles/oscap/content/*redhat* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*rhel* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*centos* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/*fedora* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content

# Clean the preinstalled configuration assesment files
rm -f ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/sca/*

# Install configuration assesment files and files templates
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/{applications,generic}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/{1,2}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/{7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/{15,16,17,18}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/{7,8,9}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/{12,14,16}/04
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/{7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/{11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/{11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sunos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/windows

cp -r etc/sca/{applications,generic,darwin,debian,rhel,sles,sunos,windows} ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp

cp etc/templates/config/generic/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/generic

cp etc/templates/config/amzn/1/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/1
cp etc/templates/config/amzn/2/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/2

cp etc/templates/config/centos/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos
cp etc/templates/config/centos/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/6
cp etc/templates/config/centos/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/5

cp etc/templates/config/darwin/15/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/15
cp etc/templates/config/darwin/16/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/16
cp etc/templates/config/darwin/17/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/17
cp etc/templates/config/darwin/18/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/18

cp etc/templates/config/rhel/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel
cp etc/templates/config/rhel/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/6
cp etc/templates/config/rhel/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/5

cp etc/templates/config/sles/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles
cp etc/templates/config/sles/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/11

cp etc/templates/config/suse/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse
cp etc/templates/config/suse/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/11

cp etc/templates/config/ubuntu/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu
cp etc/templates/config/ubuntu/12/04/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04
cp etc/templates/config/ubuntu/14/04/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04

cp etc/templates/config/debian/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian
cp etc/templates/config/debian/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/7
cp etc/templates/config/debian/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/8

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/systemd
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/fedora
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/rhel
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/suse
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/sles

# Add SUSE initscript
cp -rp src/init/ossec-hids-suse.init ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init/

# Copy scap templates
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/generic
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/centos
cp -rp  etc/templates/config/fedora/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/fedora
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/rhel
cp -rp  etc/templates/config/suse/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/suse
cp -rp  etc/templates/config/sles/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/sles

install -m 0640 src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/
cp src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/
cp -r src/systemd/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/systemd

if [ %{_debugenabled} == "yes" ]; then
  %{_rpmconfigdir}/find-debuginfo.sh
fi
exit 0
%pre

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
fi

%post
# If the package is being installed
if [ $1 = 1 ]; then
  . %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init/dist-detect.sh

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
    install -m 755 %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init/ossec-hids-suse.init /etc/init.d/wazuh-agent
  fi

  touch %{_localstatedir}/ossec/logs/active-responses.log
  chown ossec:ossec %{_localstatedir}/ossec/logs/active-responses.log
  chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log

  # Generating osse.conf file
  %{_localstatedir}/ossec/packages_files/agent_installation_scripts/gen_ossec.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir}/ossec > %{_localstatedir}/ossec/etc/ossec.conf
  chown root:ossec %{_localstatedir}/ossec/etc/ossec.conf

  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/packages_files/agent_installation_scripts/add_localfiles.sh %{_localstatedir}/ossec >> %{_localstatedir}/ossec/etc/ossec.conf
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf.rpmorig ]; then
      %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init/replace_manager_ip.sh %{_localstatedir}/ossec/etc/ossec.conf.rpmorig %{_localstatedir}/ossec/etc/ossec.conf
  fi

  /sbin/chkconfig --add wazuh-agent
  /sbin/chkconfig wazuh-agent on

  # If systemd is installed, add the wazuh-agent.service file to systemd files directory
  if [ -d /run/systemd/system ]; then

    # Fix for RHEL 8 and CentOS 8
    # Service must be installed in /usr/lib/systemd/system/
    if [ "${DIST_NAME}" == "rhel" -a "${DIST_VER}" == "8" ] || [ "${DIST_NAME}" == "centos" -a "${DIST_VER}" == "8" ]; then
      install -m 644 %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/systemd/wazuh-agent.service /usr/lib/systemd/system/
    else
      install -m 644 %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/systemd/wazuh-agent.service /etc/systemd/system/
    fi
    # Fix for Fedora 28
    # Check if SELinux is installed. If it is installed, restore the context of the .service file
    if [ "${DIST_NAME}" == "fedora" -a "${DIST_VER}" == "28" ]; then
      if command -v restorecon > /dev/null 2>&1 ; then
        restorecon -v /etc/systemd/system/wazuh-agent.service > /dev/null 2>&1
      fi
    fi
    systemctl daemon-reload
    systemctl stop wazuh-agent
    systemctl enable wazuh-agent > /dev/null 2>&1
  fi

  # Register and configure agent if Wazuh environment variables are defined
  %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/init/register_configure_agent.sh > /dev/null || :

fi

if [ ! -d /run/systemd/system ]; then
  update-rc.d wazuh-agent defaults > /dev/null 2>&1
fi

# Delete the installation files used to configure the agent
rm -rf %{_localstatedir}/ossec/packages_files

# Remove unnecessary files from shared directory
rm -f %{_localstatedir}/ossec/etc/shared/*.rpmnew

if [ $1 = 2 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.bck ]; then
      mv %{_localstatedir}/ossec/etc/ossec.bck %{_localstatedir}/ossec/etc/ossec.conf
  fi
fi

# CentOS
if [ -r "/etc/centos-release" ]; then
  DIST_NAME="centos"
  DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
# Fedora
elif [ -r "/etc/fedora-release" ]; then
    DIST_NAME="generic"
    DIST_VER=""
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

SCA_DIR="${DIST_NAME}/${DIST_VER}"
SCA_BASE_DIR="%{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp"
mkdir -p %{_localstatedir}/ossec/ruleset/sca

SCA_TMP_DIR="${SCA_BASE_DIR}/${SCA_DIR}"

# Install the configuration files needed for this hosts
if [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/sca.files" ]; then
  SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}"
else
  SCA_TMP_DIR="${SCA_BASE_DIR}/generic"
fi

SCA_TMP_FILE="${SCA_TMP_DIR}/sca.files"

if [ -r ${SCA_TMP_FILE} ]; then

  rm -f %{_localstatedir}/ossec/ruleset/sca/* || true

  for sca_file in $(cat ${SCA_TMP_FILE}); do
    mv ${SCA_BASE_DIR}/${sca_file} %{_localstatedir}/ossec/ruleset/sca
  done
fi

# Set the proper selinux context
if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ "${DIST_VER}" == "5" ]; then
  if command -v getenforce > /dev/null 2>&1; then
    if [ $(getenforce) !=  "Disabled" ]; then
      chcon -t textrel_shlib_t  %{_localstatedir}/ossec/lib/libwazuhext.so
    fi
  fi
else
  # Add the SELinux policy
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) != "Disabled" ]; then
      semodule -i %{_localstatedir}/ossec/var/selinux/wazuh.pp
      semodule -e wazuh
    fi
  fi
fi

# Restore ossec.conf permissions after upgrading
chmod 0660 %{_localstatedir}/ossec/etc/ossec.conf

if [ -s %{_localstatedir}/ossec/etc/client.keys ]; then

  if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<server-ip>).*(?=</server-ip>)' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null 2>&1; then
    /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
  fi

  if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<server-hostname>).*(?=</server-hostname>)' > /dev/null 2>&1; then
    /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
  fi

  if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<address>).*(?=</address>)' | grep -v 'MANAGER_IP' > /dev/null 2>&1; then
    /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
  fi

fi

%preun

if [ $1 = 0 ]; then

  /sbin/service wazuh-agent stop > /dev/null 2>&1 || :
  %{_localstatedir}/ossec/bin/ossec-control stop > /dev/null 2>&1
  /sbin/chkconfig wazuh-agent off > /dev/null 2>&1
  /sbin/chkconfig --del wazuh-agent

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
    rm -f /etc/init.d/wazuh-agent
  fi
  # Remove the wazuh-agent.service file
  # RHEL 8 service located in /usr/lib/systemd/system/
  if [ -f /usr/lib/systemd/system/wazuh-agent.service ]; then
    rm -f /usr/lib/systemd/system/wazuh-agent.service
  else
    rm -f /etc/systemd/system/wazuh-agent.service
  fi

  # Remove SCA files
  rm -f %{_localstatedir}/ossec/ruleset/sca/*

fi

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/ossec/etc
 chown root:ossec %{_localstatedir}/ossec/etc/localtime
 chmod 0640 %{_localstatedir}/ossec/etc/localtime

%postun

# If the package is been uninstalled
if [ $1 == 0 ];then
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

  # Remove lingering folders and files
  rm -rf %{_localstatedir}/ossec/etc/shared/
  rm -rf %{_localstatedir}/ossec/queue/
  rm -rf %{_localstatedir}/ossec/var/
  rm -rf %{_localstatedir}/ossec/bin/
  rm -rf %{_localstatedir}/ossec/logs/
  rm -rf %{_localstatedir}/ossec/backup/
  rm -rf %{_localstatedir}/ossec/ruleset/
  rm -rf %{_localstatedir}/ossec/tmp
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
    # Restart the agent
    if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<server-ip>).*(?=</server-ip>)' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null 2>&1; then
      /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
    fi

    if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<server-hostname>).*(?=</server-hostname>)' > /dev/null 2>&1; then
      /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
    fi

    if cat %{_localstatedir}/ossec/etc/ossec.conf | grep -o -P '(?<=<address>).*(?=</address>)' | grep -v 'MANAGER_IP' > /dev/null 2>&1; then
      /sbin/service wazuh-agent restart > /dev/null 2>&1 || :
    fi
  fi
fi


%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%{_initrddir}/*
%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%dir %attr(750,root,ossec) %{_localstatedir}/ossec
%attr(750,root,ossec) %{_localstatedir}/ossec/agentless
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/.ssh
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/active-response
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin/*
%dir %attr(750,root,root) %{_localstatedir}/ossec/bin
%attr(750,root,root) %{_localstatedir}/ossec/bin/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/backup
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/etc
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/client.keys
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/localtime
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/local_internal_options.conf
%attr(660,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/ossec.conf
%{_localstatedir}/ossec/etc/ossec-init.conf
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/wpk_root.pem
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/etc/shared
%attr(660,root,ossec) %config(missingok,noreplace) %{_localstatedir}/ossec/etc/shared/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/lib
%attr(750,root,ossec) %{_localstatedir}/ossec/lib/*
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/logs
%attr(660,ossec,ossec) %ghost %{_localstatedir}/ossec/logs/active-responses.log
%attr(660,root,ossec) %ghost %{_localstatedir}/ossec/logs/ossec.log
%attr(660,root,ossec) %ghost %{_localstatedir}/ossec/logs/ossec.json
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/logs/ossec
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/gen_ossec.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/generic/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/centos/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/fedora/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/rhel/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/sles/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/etc/templates/config/suse/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/packages_files/agent_installation_scripts/src/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/queue
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/queue/ossec
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/queue/diff
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/queue/alerts
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/queue/rids
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset/
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/ruleset/sca
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/applications
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/applications/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/generic
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/generic/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/1
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/1/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/2
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/amzn/2/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/5
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/5/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/6
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/6/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/centos/7
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/15
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/15/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/16
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/16/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/17
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/17/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/18
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/darwin/18/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/sca.files
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/*yml
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/7
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/7/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/8
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/8/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/debian/9
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/5
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/5/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/6
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/6/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/7
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/rhel/7/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/11
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/11/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/12
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sles/12/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sunos
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/sunos/*
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/11
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/11/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/suse/12
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/12
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/14
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/16
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/ubuntu/16/04
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/windows
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/ossec/tmp/sca-%{version}-%{release}-tmp/windows/*
%dir %attr(1770,root,ossec) %{_localstatedir}/ossec/tmp
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/var
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/incoming
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/run
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/selinux
%attr(640,root,ossec) %{_localstatedir}/ossec/var/selinux/*
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/upgrade
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles/aws
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/aws/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles/docker
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/docker/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/oscap.py
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/template*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/content
%attr(640,root,ossec) %{_localstatedir}/ossec/wodles/oscap/content/*


%changelog
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
* Tue Jul 12 2019 support <info@wazuh.com> - 3.9.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Tue Jun 11 2019 support <info@wazuh.com> - 3.9.3
- More info: https://documentation.wazuh.com/current/release-notes/
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
* Thu Dec 21 2017 support <support@wazuh.com> - 3.1.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 06 2017 support <support@wazuh.com> - 3.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon May 29 2017 support <support@wazuh.com> - 2.0.1
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
