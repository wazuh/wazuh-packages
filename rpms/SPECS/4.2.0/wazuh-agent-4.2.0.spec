Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-agent
Version:     4.2.0
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

./gen_ossec.sh conf agent centos %rhel %{_localstatedir} > etc/ossec-agent.conf
./gen_ossec.sh init agent %{_localstatedir} > ossec-init.conf

%build
pushd src
# Rebuild for agent
make clean

%if 0%{?el} >= 6 || 0%{?rhel} >= 6
    make deps
    make -j%{_threads} TARGET=agent USE_SELINUX=yes PREFIX=%{_localstatedir} DEBUG=%{_debugenabled}
%else
    %ifnarch x86_64
      MSGPACK="USE_MSGPACK_OPT=no"
    %endif
    make deps RESOURCES_URL=http://packages.wazuh.com/deps/4.2
    make -j%{_threads} TARGET=agent USE_AUDIT=no USE_SELINUX=yes USE_EXEC_ENVIRON=no PREFIX=%{_localstatedir} DEBUG=%{_debugenabled} ${MSGPACK}

%endif

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_INSTALL_TYPE="agent"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="%{_localstatedir}"' >> ./etc/preloaded-vars.conf
echo 'USER_DELETE_DIR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ACTIVE_RESPONSE="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCOLLECTOR="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_CISCAT="y"' >> ./etc/preloaded-vars.conf
echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
echo 'USER_AGENT_SERVER_IP="MANAGER_IP"' >> ./etc/preloaded-vars.conf
echo 'USER_CA_STORE="/path/to/my_cert.pem"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf
./install.sh

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/.ssh

# Copy the installed files into RPM_BUILD_ROOT directory
cp -pr %{_localstatedir}/* ${RPM_BUILD_ROOT}%{_localstatedir}/
mkdir -p ${RPM_BUILD_ROOT}/usr/lib/systemd/system/
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0755 src/init/ossec-hids-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-agent
install -m 0644 src/systemd/wazuh-agent.service ${RPM_BUILD_ROOT}/usr/lib/systemd/system/

# Clean the preinstalled configuration assesment files
rm -f ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/sca/*

# Install configuration assesment files and files templates
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/{applications,generic}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/{1,2}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/{8,7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/{15,16,17,18,19}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/{7,8,9}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/{12,14,16}/04
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/{8,7,6,5}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/{11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/{11,12}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows

cp -r ruleset/sca/{applications,generic,centos,darwin,debian,rhel,sles,sunos,windows} ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp

cp etc/templates/config/generic/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic

cp etc/templates/config/amzn/1/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1
cp etc/templates/config/amzn/2/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2

cp etc/templates/config/centos/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos
cp etc/templates/config/centos/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7
cp etc/templates/config/centos/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6
cp etc/templates/config/centos/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5

cp etc/templates/config/darwin/15/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/15
cp etc/templates/config/darwin/16/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/16
cp etc/templates/config/darwin/17/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/17
cp etc/templates/config/darwin/18/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/18
cp etc/templates/config/darwin/19/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/19

cp etc/templates/config/rhel/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel
cp etc/templates/config/rhel/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7
cp etc/templates/config/rhel/6/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6
cp etc/templates/config/rhel/5/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5

cp etc/templates/config/sles/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles
cp etc/templates/config/sles/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11

cp etc/templates/config/suse/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse
cp etc/templates/config/suse/11/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11

cp etc/templates/config/ubuntu/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu
cp etc/templates/config/ubuntu/12/04/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04
cp etc/templates/config/ubuntu/14/04/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04
cp etc/templates/config/ubuntu/16/04/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/16/04

cp etc/templates/config/debian/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian
cp etc/templates/config/debian/7/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/7
cp etc/templates/config/debian/8/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/8
cp etc/templates/config/debian/9/sca.files ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/9

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/rhel
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/suse
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/sles

# Add SUSE initscript
cp -rp src/init/ossec-hids-suse.init ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/init/

# Copy scap templates
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/generic
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/centos
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/rhel
cp -rp  etc/templates/config/suse/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/suse
cp -rp  etc/templates/config/sles/* ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/sles

install -m 0640 src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/
cp src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/packages_files/agent_installation_scripts/src/

if [ %{_debugenabled} = "yes" ]; then
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
  useradd -g ossec -G ossec -d %{_localstatedir} -r -s /sbin/nologin ossec
fi

# Stop the services to upgrade the package
if [ $1 = 2 ]; then
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-agent > /dev/null 2>&1; then
    systemctl stop wazuh-agent.service > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-agent status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-agent stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  elif %{_localstatedir}/bin/wazuh-control status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1
    touch %{_localstatedir}/tmp/wazuh.restart
  fi
fi

%post
# If the package is being installed
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
    install -m 755 %{_localstatedir}/packages_files/agent_installation_scripts/src/init/ossec-hids-suse.init /etc/init.d/wazuh-agent
  fi

  touch %{_localstatedir}/logs/active-responses.log
  chown ossec:ossec %{_localstatedir}/logs/active-responses.log
  chmod 0660 %{_localstatedir}/logs/active-responses.log

  . %{_localstatedir}/packages_files/agent_installation_scripts/src/init/dist-detect.sh

  # Generating osse.conf file
  %{_localstatedir}/packages_files/agent_installation_scripts/gen_ossec.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir} > %{_localstatedir}/etc/ossec.conf
  chown root:ossec %{_localstatedir}/etc/ossec.conf

  # Add default local_files to ossec.conf
  %{_localstatedir}/packages_files/agent_installation_scripts/add_localfiles.sh %{_localstatedir} >> %{_localstatedir}/etc/ossec.conf

  # Register and configure agent if Wazuh environment variables are defined
  %{_localstatedir}/packages_files/agent_installation_scripts/src/init/register_configure_agent.sh > /dev/null || :
fi

# Delete the installation files used to configure the agent
rm -rf %{_localstatedir}/packages_files

# Remove unnecessary files from shared directory
rm -f %{_localstatedir}/etc/shared/*.rpmnew


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
SCA_BASE_DIR="%{_localstatedir}/tmp/sca-%{version}-%{release}-tmp"
mkdir -p %{_localstatedir}/ruleset/sca

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

  rm -f %{_localstatedir}/ruleset/sca/* || true

  for sca_file in $(cat ${SCA_TMP_FILE}); do
    if [ -f ${SCA_BASE_DIR}/${sca_file} ]; then
      mv ${SCA_BASE_DIR}/${sca_file} %{_localstatedir}/ruleset/sca
    fi
  done
fi

# Set the proper selinux context
if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ "${DIST_VER}" == "5" ]; then
  if command -v getenforce > /dev/null 2>&1; then
    if [ $(getenforce) !=  "Disabled" ]; then
      chcon -t textrel_shlib_t  %{_localstatedir}/lib/libwazuhext.so
    fi
  fi
else
  # Add the SELinux policy
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) != "Disabled" ]; then
      semodule -i %{_localstatedir}/var/selinux/wazuh.pp
      semodule -e wazuh
    fi
  fi
fi

# Restore ossec.conf permissions after upgrading
chmod 0660 %{_localstatedir}/etc/ossec.conf

%preun

if [ $1 = 0 ]; then

  # Stop the services before uninstall the package
  # Check for systemd
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-agent > /dev/null 2>&1; then
    systemctl stop wazuh-agent.service > /dev/null 2>&1
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-agent status 2>/dev/null | grep "running" > /dev/null 2>&1; then
    service wazuh-agent stop > /dev/null 2>&1
  else # Anything else
    %{_localstatedir}/bin/wazuh-control stop > /dev/null 2>&1
  fi

  # Check for systemd
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1; then
    systemctl disable wazuh-agent > /dev/null 2>&1
    systemctl daemon-reload > /dev/null 2>&1
  # Check for SysV
  elif command -v service > /dev/null 2>&1 ; then
    chkconfig wazuh-agent off > /dev/null 2>&1
    chkconfig --del wazuh-agent > /dev/null 2>&1
  fi

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

  # Remove SCA files
  rm -f %{_localstatedir}/ruleset/sca/*

fi

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/etc
 chown root:ossec %{_localstatedir}/etc/localtime
 chmod 0640 %{_localstatedir}/etc/localtime

%postun

# If the package is been uninstalled
if [ $1 = 0 ];then
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
  rm -rf %{_localstatedir}/etc/shared/
  rm -rf %{_localstatedir}/queue/
  rm -rf %{_localstatedir}/var/
  rm -rf %{_localstatedir}/bin/
  rm -rf %{_localstatedir}/logs/
  rm -rf %{_localstatedir}/backup/
  rm -rf %{_localstatedir}/ruleset/
  rm -rf %{_localstatedir}/tmp
fi

# posttrans code is the last thing executed in a install/upgrade
%posttrans
if [ -f %{_localstatedir}/tmp/wazuh.restart ]; then
  rm -f %{_localstatedir}/tmp/wazuh.restart
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
    systemctl restart wazuh-agent.service > /dev/null 2>&1
  elif command -v service > /dev/null 2>&1 && service wazuh-agent status 2>/dev/null | grep "running" > /dev/null 2>&1; then
    service wazuh-agent restart > /dev/null 2>&1
  else
    %{_localstatedir}/bin/wazuh-control restart > /dev/null 2>&1
  fi
fi

%clean
rm -fr %{buildroot}

%files
%{_initrddir}/wazuh-agent
/usr/lib/systemd/system/wazuh-agent.service
%defattr(-,root,root)
%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%dir %attr(750,root,ossec) %{_localstatedir}
%attr(750,root,ossec) %{_localstatedir}/agentless
%dir %attr(770,root,ossec) %{_localstatedir}/.ssh
%dir %attr(750,root,ossec) %{_localstatedir}/active-response
%dir %attr(750,root,ossec) %{_localstatedir}/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/active-response/bin/*
%dir %attr(750,root,root) %{_localstatedir}/bin
%attr(750,root,root) %{_localstatedir}/bin/*
%dir %attr(750,root,ossec) %{_localstatedir}/backup
%dir %attr(770,ossec,ossec) %{_localstatedir}/etc
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/client.keys
%attr(640,root,ossec) %{_localstatedir}/etc/internal_options*
%attr(640,root,ossec) %{_localstatedir}/etc/localtime
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/local_internal_options.conf
%attr(660,root,ossec) %config(noreplace) %{_localstatedir}/etc/ossec.conf
%{_localstatedir}/etc/ossec-init.conf
%attr(640,root,ossec) %{_localstatedir}/etc/wpk_root.pem
%dir %attr(770,root,ossec) %{_localstatedir}/etc/shared
%attr(660,root,ossec) %config(missingok,noreplace) %{_localstatedir}/etc/shared/*
%dir %attr(750,root,ossec) %{_localstatedir}/lib
%attr(750,root,ossec) %{_localstatedir}/lib/*
%dir %attr(770,ossec,ossec) %{_localstatedir}/logs
%attr(660,ossec,ossec) %ghost %{_localstatedir}/logs/active-responses.log
%attr(660,root,ossec) %ghost %{_localstatedir}/logs/ossec.log
%attr(660,root,ossec) %ghost %{_localstatedir}/logs/ossec.json
%dir %attr(750,ossec,ossec) %{_localstatedir}/logs/ossec
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files
%dir %attr(750, root, root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/gen_ossec.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/generic/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/centos/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/rhel/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/sles/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/etc/templates/config/suse/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/packages_files/agent_installation_scripts/src/*
%dir %attr(750,root,ossec) %{_localstatedir}/queue
%dir %attr(770,ossec,ossec) %{_localstatedir}/queue/ossec
%dir %attr(750,ossec,ossec) %{_localstatedir}/queue/diff
%dir %attr(750,ossec,ossec) %{_localstatedir}/queue/fim
%dir %attr(750,ossec,ossec) %{_localstatedir}/queue/fim/db
%dir %attr(770,ossec,ossec) %{_localstatedir}/queue/alerts
%dir %attr(750,ossec,ossec) %{_localstatedir}/queue/rids
%dir %attr(750,ossec,ossec) %{_localstatedir}/queue/logcollector
%dir %attr(750, root, ossec) %{_localstatedir}/ruleset/
%dir %attr(750, root, ossec) %{_localstatedir}/ruleset/sca
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/applications
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/applications/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/generic/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/1/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/amzn/2/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/5/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/6/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/7/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/8
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/centos/8/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/15
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/15/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/16
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/16/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/17
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/17/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/18
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/darwin/18/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/sca.files
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/*yml
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/7
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/7/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/8
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/8/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/9
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/debian/9/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/5/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/6/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/7/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/8
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/rhel/8/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/11/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/12
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sles/12/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/sunos/*
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/11/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/suse/12
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/sca.files
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/12
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/12/04/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/14
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/14/04/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/16
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/16/04
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/ubuntu/16/04/*
%dir %attr(750, ossec, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows
%attr(640, root, ossec) %config(missingok) %{_localstatedir}/tmp/sca-%{version}-%{release}-tmp/windows/*
%dir %attr(1770,root,ossec) %{_localstatedir}/tmp
%dir %attr(750,root,ossec) %{_localstatedir}/var
%dir %attr(770,root,ossec) %{_localstatedir}/var/incoming
%dir %attr(770,root,ossec) %{_localstatedir}/var/run
%dir %attr(770,root,ossec) %{_localstatedir}/var/selinux
%attr(640,root,ossec) %{_localstatedir}/var/selinux/*
%dir %attr(770,root,ossec) %{_localstatedir}/var/upgrade
%dir %attr(770,root,ossec) %{_localstatedir}/var/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/wodles/aws
%attr(750,root,ossec) %{_localstatedir}/wodles/aws/*
%dir %attr(750,root,ossec) %{_localstatedir}/wodles/docker
%attr(750,root,ossec) %{_localstatedir}/wodles/docker/*
%dir %attr(750, root, ossec) %{_localstatedir}/wodles/gcloud
%attr(750, root, ossec) %{_localstatedir}/wodles/gcloud/*

%if %{_debugenabled} == "yes"
/usr/lib/debug/%{_localstatedir}/*
/usr/src/debug/%{name}-%{version}/*
%endif


%changelog
* Mon Apr 26 2021 support <info@wazuh.com> - 4.2.0
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
- Fixed daemon list for service reloading at wazuh-control.
- Fixed socket waiting issue on Windows agents.
- Fixed PCI_DSS definitions grouping issue at Rootcheck controls.
