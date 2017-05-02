Summary:     The Wazuh Manager
Name:        wazuh-manager
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
Conflicts:   ossec-hids ossec-hids-agent wazuh-agent

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

 
Requires:  expect logrotate
 
ExclusiveOS: linux
 
%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring 
hosts at an operating system and application level. It provides the following capabilities: 
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q

%if  "%_vendor" == "fedora"
./gen_ossec.sh conf manager %_vendor %fedora  > etc/ossec-server.conf
%endif

%if  "%_vendor" == "redhat" || "%_vendor" == "centos"
./gen_ossec.sh conf manager %_vendor %rhel  > etc/ossec-server.conf
%endif

./gen_ossec.sh init manager  > ossec-init.conf 
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
#make DATABASE=mysql MAXAGENTS=16384 USE_GEOIP=1 TARGET=server V=1
make TARGET=server 
popd
 
%install
# Clean BUILDROOT
rm -fr %{buildroot}
 
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/backup/agents
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/integrations
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/{bin,stats,tmp}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/{decoders,lists,rules,shared,init.d}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/logs/{alerts,archives,firewall}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lua/{compiled,native}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/queue/{agent-info,agentless,alerts,diff,fts,ossec,rids,rootcheck,syscheck}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/run
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/{decoders,rules}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/wodles
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/db/agents
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic

install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0640 src/init/inst-functions.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/template-select.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/shared.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
#install -m 0640 gen_ossec.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp
install -m 0640 add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp


cp %{SOURCE2} CHANGELOG

install -m 0640 src/init/inst-functions.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init

install -m 0755 %{SOURCE1} ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-manager
install -m 0640 etc/decoders/*.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/decoders
install -m 0440 etc/local_decoder.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/decoders
install -m 0440 src/update/ruleset/RULESET_VERSION  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/VERSION
install -m 0750 integrations/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/integrations
install -m 0640 etc/rules/*xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/rules
install -m 0640 etc/local_rules.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/rules
install -m 0550 src/agent_control ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/clear_stats ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/list_agents ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/manage_agents ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-agentlessd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-analysisd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-authd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-csyslogd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-dbd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-execd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-logcollector ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-integratord ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-logtest ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/external/lua-5.2.3/src/ossec-lua ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/external/lua-5.2.3/src/ossec-luac ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-maild ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-makelists ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-monitord ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-regex ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-remoted ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-reportd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-syscheckd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/rootcheck_control ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/syscheck_control ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/syscheck_update ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/verify-agent-conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 contrib/util.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/wazuh-modulesd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0640 etc/internal_options* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0660 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared
install -m 0750 active-response/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0750 active-response/firewalls/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0550 src/agentlessd/scripts/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
install -m 0751 src/update/ruleset/update_ruleset.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0750 wodles/oscap/oscap.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0750 wodles/oscap/template_oval.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0750 wodles/oscap/template_xccdf.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0640 etc/local_internal_options.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0640 etc/lists/audit-keys ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists
install -m 0640 etc/lists/audit-keys.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists

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


cp -pr etc/ossec-server.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/ossec.conf
cp -pr src/init/ossec-server.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/ossec-control
  
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
install -m 0644 %{SOURCE3} ${RPM_BUILD_ROOT}/etc/logrotate.d/wazuh-manager

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
 
if ! id -u ossecr > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir}/ossec \
        -r -s /sbin/nologin ossecr
fi
 
if ! id -u ossecm > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir}/ossec \
        -r -s /sbin/nologin ossecm
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
        BACKUP_RULESET="%{_localstatedir}/ossec/etc/backup_ruleset"
        mkdir $BACKUP_RULESET > /dev/null 2>&1
        chmod 750 $BACKUP_RULESET > /dev/null 2>&1
        chown root:ossec $BACKUP_RULESET > /dev/null 2>&1

        # Backup decoders: Wazuh v1.0.1 to v1.1.1
        old_decoders="ossec_decoders wazuh_decoders"
        for old_decoder in $old_decoders
        do
            if [ -d "%{_localstatedir}/ossec/ossec/etc/$old_decoder" ]; then
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

    	passlist="%{_localstatedir}/ossec/agentless/.passlist"

    	if [ -f $passlist ] && ! base64 -d $passlist > /dev/null 2>&1; then
          cp $passlist $passlist.bak
          base64 $passlist.bak > $passlist

          if [ $? = 0 ]; then
              echo "Agentless passlist encoded successfully."
              rm -f $passlist.bak
          else
              echo "ERROR: Couldn't encode Agentless passlist."
              mv $passlist.bak $passlist
          fi
        fi

  	touch %{_localstatedir}/ossec/logs/ossec.log
	touch %{_localstatedir}/ossec/logs/integrations.log
  	touch %{_localstatedir}/ossec/logs/active-responses.log
  	touch %{_localstatedir}/ossec/etc/client.keys
  	chown ossec:ossec %{_localstatedir}/ossec/logs/ossec.log
  	chown ossecm:ossec %{_localstatedir}/ossec/logs/integrations.log
  	chown ossec:ossec %{_localstatedir}/ossec/logs/active-responses.log
  	chown root:ossec %{_localstatedir}/ossec/etc/client.keys
  	chmod 0660 %{_localstatedir}/ossec/logs/ossec.log
  	chmod 0640  %{_localstatedir}/ossec/logs/integrations.log
  	chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log
  	chmod 0640 %{_localstatedir}/ossec/etc/client.keys

  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/tmp/add_localfiles.sh >>  %{_localstatedir}/ossec/etc/ossec.conf
  echo "=========================================================================================================="
  echo "= Based in your current configuration, the local_files have been added to your /var/ossec/etc/ossec.conf ="
  echo "=========================================================================================================="
   /sbin/chkconfig --add wazuh-manager
   /sbin/chkconfig wazuh-manager on
   
fi
  rm -f %{_localstatedir}/ossec/tmp/add_localfiles.sh
  rm -rf %{_localstatedir}/ossec/tmp/src
  rm -rf %{_localstatedir}/ossec/tmp/etc
  ln -sf %{_sysconfdir}/ossec-init.conf %{_localstatedir}/ossec/etc/ossec-init.conf

if [ $1 = 2 ]; then
  if [ -f /opt/ossec/etc/ossec.bck ]; then
      mv /opt/ossec/etc/ossec.bck /opt/ossec/etc/ossec.conf
  fi
fi
/sbin/service wazuh-manager restart || :
 
%preun
 
if [ $1 = 0 ]; then
  /sbin/chkconfig wazuh-manager off
  /sbin/chkconfig --del wazuh-manager
 
  /sbin/service wazuh-manager stop || :
 
  rm -f %{_localstatedir}/ossec/etc/localtime
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
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/backup
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/backup/agents
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/integrations
%attr(750,root,ossec) %{_localstatedir}/ossec/integrations/*
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/active-response
%attr(750,root,root) %dir %{_localstatedir}/ossec/bin
%attr(750,root,root) %{_localstatedir}/ossec/bin/*
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/etc
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/shared
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/etc/decoders
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/etc/rules
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/var
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/run
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/db
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/db/agents
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/archives
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/firewall
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua/compiled
%attr(750,root,root) %dir %{_localstatedir}/ossec/lua/native
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/queue
%attr(770,ossecr,ossec) %dir %{_localstatedir}/ossec/queue/agent-info
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/agentless
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/queue/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/fts
%attr(770,ossecr,ossec) %dir %{_localstatedir}/ossec/queue/rids
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/rootcheck
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/syscheck
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/ossec
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/diff
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset/decoders
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset/rules
%attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/ossec/agentless
%attr(700,root,ossec) %dir %{_localstatedir}/ossec/.ssh
%attr(750,root,ossec) %config(missingok,noreplace) %dir %{_localstatedir}/ossec/etc/lists
%{_initrddir}/*

%attr(640,root,ossec) %{_localstatedir}/ossec/etc/ossec.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/decoders/local_decoder.xml
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/local_internal_options.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/rules/local_rules.xml
%attr(660,root,ossec) %{_localstatedir}/ossec/etc/shared/*.txt
%attr(640,root,ossec) %config(missingok,noreplace) %{_localstatedir}/ossec/etc/lists/*
%attr(640,root,ossec) %{_localstatedir}/ossec/ruleset/VERSION
%attr(640,root,ossec) %config %{_localstatedir}/ossec/ruleset/rules/*
%attr(640,root,ossec) %config  %{_localstatedir}/ossec/ruleset/decoders/*
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/stats
%attr(1750,root,ossec) %dir %{_localstatedir}/ossec/tmp

%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap/content
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/oscap.*
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/template*
%if 0%{?rhel} >= 6 || 0%{?rhel} >= 7 ||  0%{?fedora} >= 23 || 0%{?fedora} >= 24 || 0%{?fedora} >= 25 
%attr(640,root,ossec) %{_localstatedir}/ossec/wodles/oscap/content/*
%endif
 
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/src/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/generic/*
%config(noreplace) /etc/logrotate.d/wazuh-manager

%changelog
* Fri Apr 21 2017 Jose Luis Ruiz <jose@wazuh.com> - 2.0
- First package v2.0
