Summary:     The Wazuh Agent
Name:        wazuh-agent
Version:     2.0
Release:     1%{?dist}
License:     GPL
Group:       System Environment/Daemons
Source0:     https://github.com/wazuh/ossec-wazuh/archive/%{name}-%{version}.tar.gz
Source1:     %{name}.init
Source2:     CHANGELOG
Source3:     wazuh-manager.logrotate
URL:         http://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      http://www.wazuh.com
Packager:    Jose Luis Ruiz <jose@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(post):   /sbin/chkconfig 
Requires(preun):  /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service
Conflicts:   ossec-hids ossec-hids-agent wazuh-manager

BuildRequires: coreutils glibc-devel openssl-devel
BuildRequires: sqlite-devel

%if 0%{?el5}
BuildRequires: openssl101e-devel
Requires: openssl101e
%endif

%if 0%{!?el6}
BuildRequires: inotify-tools-devel
%endif
BuildRequires: zlib-devel

Requires:  logrotate
 
ExclusiveOS: linux
 
%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q

%if  "%_vendor" == "fedora"
./gen_ossec.sh conf agent %_vendor %fedora > etc/ossec-agent.conf
%endif

%if  "%_vendor" == "redhat" || "%_vendor" == "centos"
./gen_ossec.sh conf agent %_vendor %rhel  > etc/ossec-agent.conf
%endif

./gen_ossec.sh init agent  > ossec-init.conf 
CFLAGS="$RPM_OPT_FLAGS -fpic -fPIE -Wformat -Wformat-security -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2"
LDFLAGS="-fPIE -pie -Wl,-z,relro"
SH_LDFLAGS="-fPIE -pie -Wl,-z,relro"
export CFLAGS LDFLAGS SH_LDFLAGS

%if 0%{?el5}
CFLAGS+=" -I/usr/include/openssl101e -L/usr/lib64/openssl101e -L/usr/lib/openssl101e "
%endif

pushd src
# Rebuild for server
make clean 
make TARGET=agent
popd
 
%install
# Clean BUILDROOT
rm -fr %{buildroot}


mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/logs
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lua/{compiled,native}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/queue/{alerts,diff,ossec,rids,syscheck}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/{run,wodles}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lua
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lua/compiled
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lua/native
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content


# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0640 src/init/inst-functions.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/template-select.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/shared.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/replace_manager_ip.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp


cp %{SOURCE2} CHANGELOG
install -m 0755 %{SOURCE1} ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-agent
install -m 0640 etc/internal_options* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0640 etc/local_internal_options.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0755 active-response/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0755 active-response/firewalls/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0644 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared
install -m 0650 src/agentlessd/scripts/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
install -m 0650 src/ossec-logcollector ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/ossec-syscheckd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/ossec-execd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/ossec-agentd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/manage_agents ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/agent-auth ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/
install -m 0650 src/external/lua-5.2.3/src/ossec-lua ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/external/lua-5.2.3/src/ossec-luac ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0650 src/wazuh-modulesd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin


install -m 0750 wodles/oscap/oscap.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0750 wodles/oscap/template* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap


%if  "%_vendor" == "redhat" && 0%{?el7}
  install -m 0640 wodles/oscap/content/cve-redhat-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
  install -m 0640 wodles/oscap/content/ssg-rhel-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
%endif
%if  "%_vendor" == "centos" && 0%{?el7}
  install -m 0640 wodles/oscap/content/ssg-centos-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
%endif

%if  "%_vendor" == "redhat" && 0%{?el6}
  install -m 0640 wodles/oscap/content/cve-redhat-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
  install -m 0640 wodles/oscap/content/ssg-rhel-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
%endif

%if  "%_vendor" == "centos" && 0%{?el6}
  install -m 0640 wodles/oscap/content/ssg-centos-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
%endif

%if 0%{?fedora} >= 23 || 0%{?fedora} >= 24 || 0%{?fedora} >= 25
  install -m 0640 wodles/oscap/content/ssg-fedora-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
%endif

cp -pr src/init/ossec-client.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/ossec-control
cp -pr contrib/util.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/
cp -pr etc/ossec-agent.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/ossec.conf


mkdir -p ${RPM_BUILD_ROOT}/etc/logrotate.d
install -m 0644 %{SOURCE3} ${RPM_BUILD_ROOT}/etc/logrotate.d/wazuh-agent

exit 0
%pre

if ! id -g ossec > /dev/null 2>&1; then
  groupadd -r ossec
fi
if ! id -u ossec > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir}/ossec \
        -r -s /sbin/nologin ossec
fi


# Delete old service
if [ -f /etc/init.d/ossec ]; then
  rm /etc/init.d/ossec
fi

if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf ]; then
    echo "====================================================================================="
    echo "= Backup from your ossec.conf has been created at /var/ossec/etc/ossec.conf.rpmorig ="
    echo "= Please verify your ossec.conf configuration at /var/ossec/etc/ossec.conf          ="
    echo "====================================================================================="
    mv /opt/ossec/etc/ossec.conf /opt/ossec/etc/ossec.conf.rpmorig
  fi
fi
if [ $1 = 2 ]; then
    cp -rp /opt/ossec/etc/ossec.conf /opt/ossec/etc/ossec.bck
fi
%post

if [ $1 = 1 ]; then

  touch %{_localstatedir}/ossec/etc/client.keys
  chown root:ossec %{_localstatedir}/ossec/etc/client.keys
  chmod 0640 %{_localstatedir}/ossec/etc/client.keys
  touch %{_localstatedir}/ossec/logs/ossec.log
  chown ossec:ossec %{_localstatedir}/ossec/logs/ossec.log
  chmod 660 %{_localstatedir}/ossec/logs/ossec.log

  touch %{_localstatedir}/ossec/logs/active-responses.log
  chown ossec:ossec %{_localstatedir}/ossec/logs/active-responses.log
  chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log


  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/tmp/add_localfiles.sh >>  %{_localstatedir}/ossec/etc/ossec.conf
  echo "======================================================================================================================================"
  echo "= By default, OSSEC analyses some logs found in your system. Please, review the configuration if you want to monitor any other file. ="
  echo "======================================================================================================================================"
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf.rpmorig ]; then
      %{_localstatedir}/ossec/tmp/src/init/replace_manager_ip.sh %{_localstatedir}/ossec/etc/ossec.conf.rpmorig %{_localstatedir}/ossec/etc/ossec.conf
  fi

  rm -rf %{_localstatedir}/ossec/tmp/etc
  rm -rf %{_localstatedir}/ossec/tmp/src
  rm -f %{_localstatedir}/ossec/tmp/add_localfiles.sh
  ln -sf %{_sysconfdir}/ossec-init.conf %{_localstatedir}/ossec/etc/ossec-init.conf
  /sbin/chkconfig --add wazuh-agent
  /sbin/chkconfig wazuh-agent on

fi
if [ $1 = 2 ]; then
  if [ -f /opt/ossec/etc/ossec.bck ]; then
      mv /opt/ossec/etc/ossec.bck /opt/ossec/etc/ossec.conf
  fi
fi


%preun
 
if [ $1 = 0 ]; then
  /sbin/chkconfig wazuh-agent off
  /sbin/chkconfig --del wazuh-agent

  /sbin/service wazuh-agent stop || :
fi


%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/ossec/etc
 chown root:ossec %{_localstatedir}/ossec/etc/localtime
 chmod 0640 %{_localstatedir}/ossec/etc/localtime

%clean
rm -fr %{buildroot}
  
%files
%defattr(-,root,root)
%doc BUGS CONFIG CONTRIBUTORS INSTALL LICENSE README.md CHANGELOG

%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%attr(550,root,ossec) %dir %{_localstatedir}/ossec
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua/compiled
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua/native
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap/content
%attr(700,root,ossec) %dir %{_localstatedir}/ossec/.ssh
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/active-response
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/active-response/bin
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/shared
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/queue
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/ossec
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/diff
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/queue/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/rids
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/syscheck
%attr(750,root,root) %dir %{_localstatedir}/ossec/bin
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/etc
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/var
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/run
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/wodles
%attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin/*
%attr(750,root,ossec) %{_localstatedir}/ossec/agentless
%attr(750,root,root) %{_localstatedir}/ossec/bin/*
%{_initrddir}/*
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640,root,ossec) %config(noreplace)%{_localstatedir}/ossec/etc/local_internal_options.conf
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/ossec.conf
%attr(660,root,ossec) %config %{_localstatedir}/ossec/etc/shared/*
%config(noreplace) /etc/logrotate.d/wazuh-agent
%attr(1750,root,ossec) %dir %{_localstatedir}/ossec/tmp
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/oscap.py
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/template*
%if 0%{?rhel} >= 6 || 0%{?rhel} >= 7 ||  0%{?fedora} >= 23 || 0%{?fedora} >= 24 || 0%{?fedora} >= 25
%attr(640,root,ossec) %{_localstatedir}/ossec/wodles/oscap/content/*
%endif
#Template files
%attr(750,root,root) %config(missingok)%{_localstatedir}/ossec/tmp/src/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/generic/*
%changelog
* Fri Sep 16 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.2
- First package v1.2
* Mon Jul 25 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.1.1.3
- Added epel-release as dependece.
* Sat May 21 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.1.1.2
- Fixed bug at Logcollector that inhibited alerts about file reduction.
* Thu May 12 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.1.1.1
- maild: timeout limitation, preventing it from hang in some cases.
- Updated decoders, ruleset and rootchecks from Wazuh Ruleset v1.0.8.
- Updated changes from ossec-hids repository.
- Avoid authd to rename agent if overplaced.
- Changed some log messages.
- Reordered directories for agent backups.
- Don't exit when client.keys is empty by default.
- Improved client.keys reloading capabilities.
- Fixed JSON output at rootcheck_control.
- Fixed agent compilation on OS X.
- Fixed memory issue on removing timestamps.
- Fixed segmentation fault at reported.
- Fixed segmentation fault at logcollector.
- Removed old rootcheck options.

* Mon Apr 25 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.1.0
- Re-usage of agent ID in manage_agents and authd, with time limit.
- Added option to avoid manager from exiting when there are no keys.
- Backup of the information about an agent that's going to be deleted.
- Alerting if Authd can't add an agent because of a duplicated IP.
- Integrator with Slack and PagerDuty.
- Simplified keywords for the option "frequency".
- Added custom Reply-to e-mail header.
- Added option to syscheck to avoid showing diffs on some files.
- Created agents-timestamp file to save the agents' date of adding.

* Tue Feb 9 2016 Jose Luis Ruiz <jose@wazuh.com> - 1.1.0
- First RPM ossec-wazuh
