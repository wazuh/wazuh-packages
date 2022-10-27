# Spec file for AIX systems
Name:        wazuh-local
Version:     3.1.0
Release:     1
License:     GPL
URL:         https://www.wazuh.com/
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Summary:     The Wazuh agent, used for threat detection, incident response and integrity monitoring.

Group: System Environment/Daemons
AutoReqProv: no
Source0: %{name}-%{version}.tar.gz
Conflicts: ossec-hids ossec-hids-agent wazuh-manager wazuh-agent
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: coreutils automake autoconf libtool

%description
Wazuh is an open source security monitoring solution for threat detection, integrity monitoring, incident response and compliance.

%prep
%setup -q

if ! grep "^ossec:" /etc/group > /dev/null 2>&1; then
  /usr/bin/mkgroup ossec
fi
if ! grep "^ossec:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossec
fi
if ! grep "^ossecr:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossecr
fi
if ! grep "^ossecm:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossecm
fi
/usr/sbin/usermod -G ossec ossec
/usr/sbin/usermod -G ossec ossecm
/usr/sbin/usermod -G ossec ossecr

./gen_ossec.sh init local %{_localstatedir} > ossec-init.conf
cd src && gmake clean
sed "s/-Wl,-O2/-O2 -pthread/" ../framework/Makefile > ../framework/Makefile.2 && mv ../framework/Makefile.2 ../framework/Makefile
sed "s/-Wl,-g/-pthread/" ../framework/Makefile > ../framework/Makefile.2 && mv ../framework/Makefile.2 ../framework/Makefile

gmake TARGET=local USE_SELINUX=no PREFIX=%{_localstatedir} DISABLE_SHARED=yes DISABLE_SYSC=yes
cd ..

%install
# Clean BUILDROOT
rm -fr %{buildroot}


echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf 
echo 'USER_INSTALL_TYPE="local"' >> ./etc/preloaded-vars.conf
echo 'USER_DIR="/var/ossec"' >> ./etc/preloaded-vars.conf
echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_EMAIL="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_ROOTCHECK="y"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
echo 'USER_WHITE_LIST="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_SYSLOG="n"' >> ./etc/preloaded-vars.conf
echo 'USER_ENABLE_AUTHD="n"' >> ./etc/preloaded-vars.conf
echo 'USER_AUTO_START="n"' >> ./etc/preloaded-vars.conf

DISABLE_SHARED="yes" DISABLE_SYSC="yes" ./install.sh

# Remove unnecessary files or directories
rm -rf %{_localstatedir}/selinux

# Create directories
mkdir -p ${RPM_BUILD_ROOT}%{_init_scripts}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/.ssh

# Copy the files into RPM_BUILD_ROOT directory
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0750 src/init/ossec-hids-aix.init ${RPM_BUILD_ROOT}%{_init_scripts}/wazuh-local
cp -pr %{_localstatedir}/* ${RPM_BUILD_ROOT}%{_localstatedir}/

# Add configuration scripts
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/
cp gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/
cp add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/

# Support files for dynamic creation of configuraiton file
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic
cp -pr etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic/localfile-logs
cp -pr etc/templates/config/generic/localfile-logs/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic/localfile-logs

# Support scripts for post installation
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init
cp src/init/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init

# Add installation scripts
cp src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/
cp src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/
cp src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/

mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/logs/{alerts,archives,firewall,ossec,vuls}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/queue/{agent-groups,agent-info,agentless,agents,alerts,diff,fts,ossec,rootcheck,syscheck}

exit 0

%pre

# Create ossec user and group
if ! grep "^ossec:" /etc/group > /dev/null 2>&1; then
  /usr/bin/mkgroup ossec
fi
if ! grep "^ossec" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossec
fi
if ! grep "^ossecr:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossecr
fi
if ! grep "^ossecm:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/useradd ossecm
fi
/usr/sbin/usermod -G ossec ossec
/usr/sbin/usermod -G ossec ossecm
/usr/sbin/usermod -G ossec ossecr

# Delete old service
if [ -f /etc/rc.d/init.d/wazuh-local ]; then
  rm /etc/rc.d/init.d/wazuh-local
fi

# Remove existent config file and notify user for new installations
if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/etc/ossec.conf ]; then
    echo "A backup from your ossec.conf has been created at %{_localstatedir}/etc/ossec.conf.rpmorig"
    echo "Please verify your ossec.conf configuration at %{_localstatedir}/etc/ossec.conf"
    mv %{_localstatedir}/etc/ossec.conf %{_localstatedir}/etc/ossec.conf.rpmorig
  fi
fi

# Make a backup copy of the config file for package upgrades
if [ $1 = 2 ]; then
  cp -rp %{_localstatedir}/etc/ossec.conf %{_localstatedir}/etc/ossec.bck
fi

%post
# New installations
if [ $1 = 1 ]; then

  # Generating ossec.conf file
  . %{_localstatedir}/tmp/src/init/dist-detect.sh
  %{_localstatedir}/tmp/gen_ossec.sh conf local ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir} > %{_localstatedir}/etc/ossec.conf
  sed "s/wazuh_database.sync_rootcheck=1/wazuh_database.sync_rootcheck=0/" %{_localstatedir}/etc/internal_options.conf > %{_localstatedir}/etc/internal_options.conf.tmp &&  mv %{_localstatedir}/etc/internal_options.conf.tmp %{_localstatedir}/etc/internal_options.conf
  sed "s/wazuh_database.sync_agents=1/wazuh_database.sync_agents=0/" %{_localstatedir}/etc/internal_options.conf > %{_localstatedir}/etc/internal_options.conf.tmp &&  mv %{_localstatedir}/etc/internal_options.conf.tmp %{_localstatedir}/etc/internal_options.conf
  

  ## Disable syscheck and rootcheck
  sed "s/<disabled>no</disabled>/<disabled>yes</disabled>/" %{_localstatedir}/etc/ossec.conf > %{_localstatedir}/etc/ossec.conf.tmp &&  mv %{_localstatedir}/etc/ossec.conf.tmp %{_localstatedir}/etc/ossec.conf

  chown root:ossec %{_localstatedir}/etc/ossec.conf
  chmod 0640 %{_localstatedir}/etc/ossec.conf

  # Add default local_files to ossec.conf
  %{_localstatedir}/tmp/add_localfiles.sh %{_localstatedir} >> %{_localstatedir}/etc/ossec.conf

  # Restore Wazuh manager configuration
  if [ -f %{_localstatedir}/etc/ossec.conf.rpmorig ]; then
    %{_localstatedir}/tmp/src/init/replace_manager_ip.sh %{_localstatedir}/etc/ossec.conf.rpmorig %{_localstatedir}/etc/ossec.conf
  fi

  # Fix for AIX: remove syscollector
  sed '/System inventory/,/^$/{/^$/!d;}' %{_localstatedir}/etc/ossec.conf > %{_localstatedir}/etc/ossec.conf.tmp
  mv %{_localstatedir}/etc/ossec.conf.tmp %{_localstatedir}/etc/ossec.conf

  # Fix for AIX: netstat command
  sed 's/netstat -tulpn/nestat -tu/' %{_localstatedir}/etc/ossec.conf > %{_localstatedir}/etc/ossec.conf.tmp
  mv %{_localstatedir}/etc/ossec.conf.tmp %{_localstatedir}/etc/ossec.conf
  sed 's/sort -k 4 -g/sort -n -k 4/' %{_localstatedir}/etc/ossec.conf > %{_localstatedir}/etc/ossec.conf.tmp
  mv %{_localstatedir}/etc/ossec.conf.tmp %{_localstatedir}/etc/ossec.conf

  # Generate the active-responses.log file
  touch %{_localstatedir}/logs/active-responses.log
  chown ossec:ossec %{_localstatedir}/logs/active-responses.log
  chmod 0660 %{_localstatedir}/logs/active-responses.log
fi

rm -rf %{_localstatedir}/tmp/etc
rm -rf %{_localstatedir}/tmp/src
rm -f %{_localstatedir}/tmp/add_localfiles.sh


# Restart wazuh-local when manager settings are in place
if grep '<server-ip>.*</server-ip>' %{_localstatedir}/etc/ossec.conf | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-local restart > /dev/null 2>&1 || :
fi
if grep '<server-hostname>.*</server-hostname>' %{_localstatedir}/etc/ossec.conf > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-local restart > /dev/null 2>&1 || :
fi
if grep '<address>.*</address>' %{_localstatedir}/etc/ossec.conf | grep -v 'MANAGER_IP' > /dev/null 2>&1; then
  /etc/rc.d/init.d/wazuh-local restart > /dev/null 2>&1 || :
fi


%preun

if [ $1 = 0 ]; then
  /etc/rc.d/init.d/wazuh-local stop > /dev/null 2>&1 || :
fi


%postun

# Remove ossec user and group
if [ $1 == 0 ];then
  if grep "^ossec:" /etc/passwd > /dev/null 2>&1; then
    /usr/sbin/userdel ossec
  fi
  if grep "^ossecr:" /etc/passwd > /dev/null 2>&1; then
  /usr/sbin/userdel ossecr
  fi
  if grep "^ossecm:" /etc/passwd > /dev/null 2>&1; then
    /usr/sbin/userdel ossecm
  fi
  if grep "^ossec:" /etc/group > /dev/null 2>&1; then
    /usr/sbin/rmgroup ossec
  fi
fi


%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)

%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%attr(750,root,ossec) %dir %{_localstatedir}
%attr(750,root,ossec) %dir %{_localstatedir}/active-response
%attr(750,root,ossec) %dir %{_localstatedir}/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/agentless
%attr(750,root,ossec) %dir %{_localstatedir}/backup
%attr(750,root,ossec) %dir %{_localstatedir}/bin
%attr(770,ossec,ossec) %dir %{_localstatedir}/etc
%attr(770,root,ossec) %dir %{_localstatedir}/etc/decoders
%attr(750,root,ossec) %dir %{_localstatedir}/etc/lists
%attr(750,root,ossec) %dir %{_localstatedir}/etc/lists/amazon
%attr(770,root,ossec) %dir %{_localstatedir}/etc/shared
%attr(770,root,ossec) %dir %{_localstatedir}/etc/rootcheck
%attr(770,root,ossec) %dir %{_localstatedir}/etc/rules
%attr(750,root,ossec) %dir %{_localstatedir}/framework
%attr(750,root,ossec) %dir %{_localstatedir}/framework/lib
%attr(750,root,ossec) %dir %{_localstatedir}/framework/wazuh
%attr(750,root,ossec) %dir %{_localstatedir}/integrations
%attr(770,ossec,ossec) %dir %{_localstatedir}/logs
%attr(750,ossec,ossec) %dir %{_localstatedir}/logs/archives
%attr(750,ossec,ossec) %dir %{_localstatedir}/logs/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/logs/firewall
%attr(750,ossec,ossec) %dir %{_localstatedir}/logs/ossec
%attr(750,ossec,ossec) %dir %{_localstatedir}/logs/vuls
%attr(750,root,root) %dir %{_localstatedir}/lua
%attr(750,root,root) %dir %{_localstatedir}/lua/compiled
%attr(750,root,root) %dir %{_localstatedir}/lua/native
%attr(750,root,ossec) %dir %{_localstatedir}/queue
%attr(770,ossecr,ossec) %dir %{_localstatedir}/queue/agent-info
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/agentless
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/agents
%attr(770,ossec,ossec) %dir %{_localstatedir}/queue/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/fts
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/rootcheck
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/syscheck
%attr(770,ossec,ossec) %dir %{_localstatedir}/queue/ossec
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/diff
%attr(750,root,ossec) %dir %{_localstatedir}/ruleset
%attr(750,root,ossec) %dir %{_localstatedir}/ruleset/decoders
%attr(750,root,ossec) %dir %{_localstatedir}/ruleset/rules
%attr(700,root,ossec) %dir %{_localstatedir}/.ssh
%attr(750,ossec,ossec) %dir %{_localstatedir}/stats
%attr(1750,root,ossec) %dir %{_localstatedir}/tmp
%attr(750,root,ossec) %dir %{_localstatedir}/var
%attr(770,root,ossec) %dir %{_localstatedir}/var/run
%attr(770,root,ossec) %dir %{_localstatedir}/var/db
%attr(770,root,ossec) %dir %{_localstatedir}/var/upgrade
%attr(770,root,ossec) %dir %{_localstatedir}/var/db/agents
%attr(770,root,ossec) %dir %{_localstatedir}/var/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/ciscat
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/vuls
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/oscap
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/oscap/content


%attr(640,root,ossec) %{_localstatedir}/framework/lib/*
%attr(640,root,ossec) %{_localstatedir}/framework/wazuh/*
%attr(750,root,ossec) %{_localstatedir}/integrations/*
%attr(750,root,root) %{_localstatedir}/bin/*
%attr(750,root,ossec) %{_localstatedir}/active-response/bin/*
%attr(640,root,ossec) %{_localstatedir}/etc/ossec.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/decoders/local_decoder.xml
%attr(640,root,ossec) %{_localstatedir}/etc/internal_options*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/local_internal_options.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/rules/local_rules.xml
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/lists/audit-*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/lists/amazon/*
%attr(660,root,ossec) %{_localstatedir}/etc/rootcheck/*.txt
%attr(640,root,ossec) %{_localstatedir}/ruleset/VERSION
%attr(640,root,ossec) %{_localstatedir}/ruleset/rules/*
%attr(640,root,ossec) %{_localstatedir}/ruleset/decoders/*
%attr(750,root,ossec) %{_localstatedir}/wodles/ciscat/*
%attr(750,root,ossec) %{_localstatedir}/wodles/vuls/*
%attr(750,root,ossec) %{_localstatedir}/wodles/oscap/oscap.*
%attr(750,root,ossec) %{_localstatedir}/wodles/oscap/template*
%attr(750,root,system) %config(missingok) %{_localstatedir}/tmp/add_localfiles.sh
%attr(750,root,system) %config(missingok) %{_localstatedir}/tmp/gen_ossec.sh
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/tmp/etc/templates
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/tmp/etc/templates/config
%dir %attr(1750,root,ossec) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/generic
%attr(750,root,system) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/generic/*.template
%dir %attr(1750,root,ossec) %config(missingok) /var/ossec/tmp/etc/templates/config/generic/localfile-logs
%attr(750,root,system) %config(missingok) /var/ossec/tmp/etc/templates/config/generic/localfile-logs/*.template
%attr(750,root,system) %config(missingok) %{_localstatedir}/tmp/src/*

%changelog
* Thu Dec 21 2017 support <support@wazuh.com> - 3.1.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Nov 06 2017 support <support@wazuh.com> - 3.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
