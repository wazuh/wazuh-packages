# Spec file for AIX systems
Name:        wazuh-agent
Version:     3.10.0
Release:     1
License:     GPL
URL:         https://www.wazuh.com/
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Summary:     The Wazuh agent, used for threat detection, incident response and integrity monitoring.

Group: System Environment/Daemons
AutoReqProv: no
Source0: %{name}-%{version}.tar.gz
Conflicts: ossec-hids ossec-hids-agent wazuh-manager wazuh-local
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: coreutils automake autoconf libtool

%description
Wazuh is an open source security monitoring solution for threat detection, integrity monitoring, incident response and compliance.

%prep
%setup -q
./gen_ossec.sh init agent %{_localstatedir}/ossec > ossec-init.conf
cd src && gmake clean && gmake deps RESOURCES_URL=http://packages.wazuh.com/deps/3.10
gmake TARGET=agent USE_SELINUX=no PREFIX=%{_localstatedir}/ossec DISABLE_SHARED=yes DISABLE_SYSC=yes
cd ..

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
echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_CISCAT="n"' >> ./etc/preloaded-vars.conf
echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
echo 'USER_AGENT_SERVER_IP="MANAGER_IP"' >> ./etc/preloaded-vars.conf
echo 'USER_CA_STORE="/path/to/my_cert.pem"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf
DISABLE_SHARED="yes" DISABLE_SYSC="yes" ./install.sh

# Remove unnecessary files or directories
rm -rf %{_localstatedir}/ossec/selinux

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_init_scripts}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh

# Copy the files into RPM_BUILD_ROOT directory
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0750 src/init/ossec-hids-aix.init ${RPM_BUILD_ROOT}%{_init_scripts}/wazuh-agent
cp -pr %{_localstatedir}/ossec/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/

# Support files for dynamic creation of configuraiton file
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
cp -pr etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic/localfile-logs
cp -pr etc/templates/config/generic/localfile-logs/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic/localfile-logs

# Support scripts for post installation
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
cp src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/
cp src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/

exit 0

%pre

# Create ossec user and group
if ! grep "^ossec:" /etc/group > /dev/null 2>&1; then
  /usr/bin/mkgroup ossec
fi
if ! grep "^ossec" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossec
  /usr/sbin/usermod -G ossec ossec
fi

# Delete old service
if [ -f /etc/rc.d/init.d/wazuh-agent ]; then
  rm /etc/rc.d/init.d/wazuh-agent
fi

# Remove existent config file and notify user for new installations
if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf ]; then
    echo "A backup from your ossec.conf has been created at %{_localstatedir}/ossec/etc/ossec.conf.rpmorig"
    echo "Please verify your ossec.conf configuration at %{_localstatedir}/ossec/etc/ossec.conf"
    mv %{_localstatedir}/ossec/etc/ossec.conf %{_localstatedir}/ossec/etc/ossec.conf.rpmorig
  fi
fi

# Make a backup copy of the config file for package upgrades
if [ $1 = 2 ]; then
  cp -rp %{_localstatedir}/ossec/etc/ossec.conf %{_localstatedir}/ossec/etc/ossec.bck
fi

%post
# New installations
if [ $1 = 1 ]; then

  # Generating ossec.conf file
  . %{_localstatedir}/ossec/tmp/src/init/dist-detect.sh
  %{_localstatedir}/ossec/tmp/gen_ossec.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir}/ossec > %{_localstatedir}/ossec/etc/ossec.conf
  chown root:ossec %{_localstatedir}/ossec/etc/ossec.conf

  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/tmp/add_localfiles.sh %{_localstatedir}/ossec >> %{_localstatedir}/ossec/etc/ossec.conf

  # Restore Wazuh manager configuration
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf.rpmorig ]; then
    %{_localstatedir}/ossec/tmp/src/init/replace_manager_ip.sh %{_localstatedir}/ossec/etc/ossec.conf.rpmorig %{_localstatedir}/ossec/etc/ossec.conf
  fi

  # Fix for AIX: remove syscollector
  sed '/System inventory/,/^$/{/^$/!d;}' %{_localstatedir}/ossec/etc/ossec.conf > %{_localstatedir}/ossec/etc/ossec.conf.tmp
  mv %{_localstatedir}/ossec/etc/ossec.conf.tmp %{_localstatedir}/ossec/etc/ossec.conf

  # Fix for AIX: netstat command
  sed 's/netstat -tulpn/nestat -tu/' %{_localstatedir}/ossec/etc/ossec.conf > %{_localstatedir}/ossec/etc/ossec.conf.tmp
  mv %{_localstatedir}/ossec/etc/ossec.conf.tmp %{_localstatedir}/ossec/etc/ossec.conf
  sed 's/sort -k 4 -g/sort -n -k 4/' %{_localstatedir}/ossec/etc/ossec.conf > %{_localstatedir}/ossec/etc/ossec.conf.tmp
  mv %{_localstatedir}/ossec/etc/ossec.conf.tmp %{_localstatedir}/ossec/etc/ossec.conf

  # Generate the active-responses.log file
  touch %{_localstatedir}/ossec/logs/active-responses.log
  chown ossec:ossec %{_localstatedir}/ossec/logs/active-responses.log
  chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log

  %{_localstatedir}/ossec/tmp/src/init/register_configure_agent.sh > /dev/null || :

fi

ln -fs /etc/rc.d/init.d/wazuh-agent /etc/rc.d/rc2.d/S97wazuh-agent
ln -fs /etc/rc.d/init.d/wazuh-agent /etc/rc.d/rc3.d/S97wazuh-agent

rm -rf %{_localstatedir}/ossec/tmp/etc
rm -rf %{_localstatedir}/ossec/tmp/src
rm -f %{_localstatedir}/ossec/tmp/add_localfiles.sh

chmod 0660 %{_localstatedir}/ossec/etc/ossec.conf

# Restart wazuh-agent when manager settings are in place
if grep '<server-ip>.*</server-ip>' %{_localstatedir}/ossec/etc/ossec.conf | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-agent restart > /dev/null 2>&1 || :
fi
if grep '<server-hostname>.*</server-hostname>' %{_localstatedir}/ossec/etc/ossec.conf > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-agent restart > /dev/null 2>&1 || :
fi
if grep '<address>.*</address>' %{_localstatedir}/ossec/etc/ossec.conf | grep -v 'MANAGER_IP' > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-agent restart > /dev/null 2>&1 || :
fi


%preun

/etc/rc.d/init.d/wazuh-agent stop > /dev/null 2>&1 || :

if [ $1 = 0 ]; then

  rm -f %{_localstatedir}/ossec/queue/ossec/*
  rm -f %{_localstatedir}/ossec/queue/ossec/.agent_info || :
  rm -f %{_localstatedir}/ossec/queue/ossec/.wait || :
  rm -f %{_localstatedir}/ossec/queue/diff/*
  rm -f %{_localstatedir}/ossec/queue/alerts/*
  rm -f %{_localstatedir}/ossec/queue/rids/*

fi


%postun

# Remove ossec user and group
if [ $1 = 0 ];then
  if grep "^ossec" /etc/passwd > /dev/null 2>&1; then
    userdel ossec
  fi
  if grep "^ossec:" /etc/group > /dev/null 2>&1; then
    rmgroup ossec
  fi

  rm -rf %{_localstatedir}/ossec/ruleset
fi


%clean
rm -fr %{buildroot}

%files
%{_init_scripts}/*
%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf

%dir %attr(750,root,ossec) %{_localstatedir}/ossec
%attr(750,root,ossec) %{_localstatedir}/ossec/agentless
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/.ssh
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/active-response
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin/*
%dir %attr(750,root,system) %{_localstatedir}/ossec/bin
%attr(750,root,system) %{_localstatedir}/ossec/bin/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/backup
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/etc
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/client.keys
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/local_internal_options.conf
%attr(660,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/ossec.conf
%{_localstatedir}/ossec/etc/ossec-init.conf
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/wpk_root.pem
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/etc/shared
%attr(660,root,ossec) %config(missingok,noreplace) %{_localstatedir}/ossec/etc/shared/*
%dir %attr(750,root,system) %{_localstatedir}/ossec/lib
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/logs
%attr(660,ossec,ossec) %ghost %{_localstatedir}/ossec/logs/active-responses.log
%attr(660,root,ossec) %ghost %{_localstatedir}/ossec/logs/ossec.log
%attr(660,root,ossec) %ghost %{_localstatedir}/ossec/logs/ossec.json
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/logs/ossec
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/queue
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/queue/ossec
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/queue/diff
%dir %attr(770,ossec,ossec) %{_localstatedir}/ossec/queue/alerts
%dir %attr(750,ossec,ossec) %{_localstatedir}/ossec/queue/rids
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/ruleset/sca
%attr(640, root, ossec) %{_localstatedir}/ossec/ruleset/sca/*
%dir %attr(1750,root,ossec) %{_localstatedir}/ossec/tmp
%attr(750,root,system) %config(missingok) %{_localstatedir}/ossec/tmp/add_localfiles.sh
%attr(750,root,system) %config(missingok) %{_localstatedir}/ossec/tmp/gen_ossec.sh
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/generic
%attr(750,root,system) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/generic/*.template
%dir %attr(1750,root,ossec) %config(missingok) /var/ossec/tmp/etc/templates/config/generic/localfile-logs
%attr(750,root,system) %config(missingok) /var/ossec/tmp/etc/templates/config/generic/localfile-logs/*.template
%attr(750,root,system) %config(missingok) %{_localstatedir}/ossec/tmp/src/*
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/var
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/incoming
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/run
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/upgrade
%dir %attr(770,root,ossec) %{_localstatedir}/ossec/var/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles
%dir %attr(750,root,ossec) %{_localstatedir}/ossec/wodles/aws
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/aws/*


%changelog
* Mon Aug 26 2019 support <support@wazuh.com> - 3.10.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Aug 8 2019 support <support@wazuh.com> - 3.9.5
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jul 12 2019 support <support@wazuh.com> - 3.9.4
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jul 02 2019 support <support@wazuh.com> - 3.9.3
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jun 11 2019 support <support@wazuh.com> - 3.9.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Jun 01 2019 support <support@wazuh.com> - 3.9.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Feb 25 2019 support <support@wazuh.com> - 3.9.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Jan 30 2019 support <support@wazuh.com> - 3.8.2
- More info: https://documentation.wazuh.com/current/release-notes/
* Thu Jan 24 2019 support <support@wazuh.com> - 3.8.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri Jan 18 2019 support <support@wazuh.com> - 3.8.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Nov 7 2018 support <support@wazuh.com> - 3.7.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Sep 7 2018 support <support@wazuh.com> - 3.6.0
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