Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-manager
Version:     3.2.1
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <support@wazuh.com>
Packager:    Wazuh, Inc <support@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(post):   /sbin/chkconfig
Requires(preun):  /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service /usr/sbin/groupdel /usr/sbin/userdel
Conflicts:   ossec-hids ossec-hids-agent wazuh-agent wazuh-local
AutoReqProv: no

Requires: which
BuildRequires: coreutils glibc-devel

%if 0%{?fc25}
BuildRequires: perl
%endif

%if 0%{?el5}
BuildRequires: perl
%endif


ExclusiveOS: linux

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

%prep
%setup -q

./gen_ossec.sh conf manager centos %rhel  > etc/ossec-server.conf
./gen_ossec.sh init manager  > ossec-init.conf

pushd src
# Rebuild for server
make clean

%if 0%{?el} >= 6 || 0%{?rhel} >= 6
    make -j%{_threads} TARGET=server
%else
    make -j%{_threads} TARGET=server DISABLE_SYSC=yes
%endif

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/active-response/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/agentless
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/backup/{agents,groups,shared}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/etc/{decoders,lists,rules,shared,rootcheck,init.d}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists/amazon
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/etc/shared/default
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/framework/{lib,wazuh}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/integrations
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/logs/{alerts,archives,firewall,ossec,vuls}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/lua/{compiled,native}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/queue/{agent-groups,agent-info,agentless,agents,alerts,db,diff,fts,ossec,rids,rootcheck,syscheck}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/{decoders,rules}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/.ssh
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/stats
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/var/{db,run,upgrade,wodles}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/var/db/agents
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/var/wodles
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/aws
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/vuls
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/vuls/go

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/fedora
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/rhel

cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/generic
# Copy scap templates
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/centos
cp -rp  etc/templates/config/fedora/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/fedora
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/etc/templates/config/rhel

install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0750 active-response/firewalls/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/active-response/bin
install -m 0750 active-response/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/active-response/bin
install -m 0550 src/agentlessd/scripts/* ${RPM_BUILD_ROOT}%{_localstatedir}/agentless
install -m 0550 src/agent_control ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 framework/scripts/agent_groups.py ${RPM_BUILD_ROOT}%{_localstatedir}/bin/agent_groups
install -m 0550 framework/scripts/agent_upgrade.py  ${RPM_BUILD_ROOT}%{_localstatedir}/bin/agent_upgrade
install -m 0550 framework/scripts/cluster_control.py ${RPM_BUILD_ROOT}%{_localstatedir}/bin/cluster_control
install -m 0550 framework/scripts/wazuh-clusterd.py ${RPM_BUILD_ROOT}%{_localstatedir}/bin/wazuh-clusterd

install -m 0550 src/clear_stats ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/list_agents ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/manage_agents ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-agentlessd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-analysisd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-authd ${RPM_BUILD_ROOT}%{_localstatedir}/bin

cp -pr src/init/ossec-server.sh ${RPM_BUILD_ROOT}%{_localstatedir}/bin/ossec-control
install -m 0550 src/ossec-csyslogd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-dbd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-execd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-integratord ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-logcollector ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-logtest ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/external/lua-5.2.3/src/ossec-lua ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/external/lua-5.2.3/src/ossec-luac ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-maild ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-makelists ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-monitord ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-regex ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-remoted ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-reportd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/ossec-syscheckd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/rootcheck_control ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/syscheck_control ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/syscheck_update ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0750 src/update/ruleset/update_ruleset ${RPM_BUILD_ROOT}%{_localstatedir}/bin/update_ruleset
install -m 0550 src/verify-agent-conf ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 contrib/util.sh ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0750 src/wazuh-db ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0550 src/wazuh-modulesd ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0440 etc/local_decoder.xml ${RPM_BUILD_ROOT}%{_localstatedir}/etc/decoders
install -m 0640 etc/internal_options* ${RPM_BUILD_ROOT}%{_localstatedir}/etc
install -m 0660 etc/lists/amazon/aws-eventnames ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-eventnames.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-sources ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-sources.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists/amazon
install -m 0640 etc/lists/audit-keys ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists
install -m 0640 etc/lists/audit-keys.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/etc/lists
install -m 0640 etc/local_internal_options.conf ${RPM_BUILD_ROOT}%{_localstatedir}/etc
install -m 0660 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/etc/rootcheck
install -m 0640 etc/local_rules.xml ${RPM_BUILD_ROOT}%{_localstatedir}/etc/rules
install -m 0640 etc/agent.conf ${RPM_BUILD_ROOT}%{_localstatedir}/etc/shared/default
install -m 0660 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/etc/shared/default
install -m 0640 framework/wazuh/*.py ${RPM_BUILD_ROOT}%{_localstatedir}/framework/wazuh
install -m 0660 framework/libsqlite3.so.0 ${RPM_BUILD_ROOT}%{_localstatedir}/framework/lib
install -m 0660 framework/wazuh-clusterd-internal ${RPM_BUILD_ROOT}%{_localstatedir}/bin
install -m 0640 framework/wazuh/cluster.json ${RPM_BUILD_ROOT}%{_localstatedir}/framework/wazuh/cluster.json

install -m 0640 etc/rules/*xml ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/rules
install -m 0640 etc/decoders/*.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/decoders
install -m 0440 src/update/ruleset/RULESET_VERSION  ${RPM_BUILD_ROOT}%{_localstatedir}/ruleset/VERSION
install -m 0750 integrations/* ${RPM_BUILD_ROOT}%{_localstatedir}/integrations
# AWS wodle
install -m 0750 wodles/aws/aws.py ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/aws
install -m 0750 wodles/oscap/oscap.py ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap
install -m 0750 wodles/oscap/template_oval.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap
install -m 0750 wodles/oscap/template_xccdf.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap
install -m 0640 wodles/oscap/content/cve-redhat-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-rhel-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-centos-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/cve-redhat-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-rhel-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-centos-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-fedora-24-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/oscap/content

install -m 0755 %{SOURCE1} ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-manager

# Temporal files for gent_ossec
install -m 0640 src/init/inst-functions.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init
install -m 0640 src/init/template-select.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init
install -m 0640 src/init/shared.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src/init
install -m 0640 src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src
install -m 0640 src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src
install -m 0640 src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/tmp/src
install -m 0640 add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/tmp
cp CHANGELOG.md CHANGELOG

# Vuls files
install -m 0750 wodles/vuls/deploy_vuls.sh ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/vuls
install -m 0750 wodles/vuls/vuls.py ${RPM_BUILD_ROOT}%{_localstatedir}/wodles/vuls

cp -pr etc/ossec-server.conf ${RPM_BUILD_ROOT}%{_localstatedir}/etc/ossec.conf

# Copying install scripts to /usr/share
mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/
cp gen_ossec.sh ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/
cp add_localfiles.sh ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/

mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src
cp src/VERSION ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/
cp src/REVISION ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/
cp src/LOCATION ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/

mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/init
cp -r src/init/*  ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/init

mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic
cp -r etc/templates/config/generic/* ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic

# Copy scap templates
mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos
cp -r  etc/templates/config/centos/* ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos

mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/fedora
cp -r  etc/templates/config/fedora/* ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/fedora

mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel
cp -r  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel

exit 0
%pre

# Stop Authd if it is running
if ps aux | grep /var/ossec/bin/ossec-authd | grep -v grep; then
   kill `ps -ef | grep '/var/ossec/bin/ossec-authd' | grep -v grep | awk '{print $2}'` > /dev/null 2>&1
fi

# Ensure that the wazuh-manager is stopped
if [ -d /var/ossec ]; then
  /var/ossec/bin/ossec-control stop
fi

if ! id -g ossec > /dev/null 2>&1; then
  groupadd -r ossec
fi

if ! id -u ossec > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir} \
        -r -s /sbin/nologin ossec
fi

if ! id -u ossecr > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir} \
        -r -s /sbin/nologin ossecr
fi

if ! id -u ossecm > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir} \
        -r -s /sbin/nologin ossecm
fi

if [ -d ${DIR}/var/db/agents ]; then
  rm -f ${DIR}/var/db/agents/*
fi

# Remove existing SQLite databases
rm -f %{_localstatedir}/var/db/global.db* || true
rm -f %{_localstatedir}/var/db/cluster.db* || true
rm -f %{_localstatedir}/var/db/.profile.db* || true
rm -f %{_localstatedir}/var/db/agents/* || true


# Delete old service
if [ -f /etc/init.d/ossec ]; then
  rm /etc/init.d/ossec
fi
if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/etc/ossec.conf ]; then
    echo "====================================================================================="
    echo "= Backup from your ossec.conf has been created at /var/ossec/etc/ossec.conf.rpmorig ="
    echo "= Please verify your ossec.conf configuration at /var/ossec/etc/ossec.conf          ="
    echo "====================================================================================="
    mv %{_localstatedir}/etc/ossec.conf %{_localstatedir}/etc/ossec.conf.rpmorig
  fi
fi
if [ $1 = 2 ]; then
    cp -rp %{_localstatedir}/etc/ossec.conf %{_localstatedir}/etc/ossec.bck
    cp -rp %{_localstatedir}/etc/shared %{_localstatedir}/backup/
    if [ ! -d %{_localstatedir}/etc/shared/default ]; then
      mkdir  %{_localstatedir}/etc/shared/default
      cp -rp %{_localstatedir}/backup/shared/* %{_localstatedir}/etc/shared/default || true
      rm -f  %{_localstatedir}/etc/shared/merged.mg || true
      rm -f  %{_localstatedir}/etc/shared/default/ar.conf || true
    fi
fi
%post

if [ $1 = 1 ]; then


  # Generating osse.conf file
  . /usr/share/wazuh-manager/scripts/tmp/src/init/dist-detect.sh
  /usr/share/wazuh-manager/scripts/tmp/gen_ossec.sh conf manager ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} > %{_localstatedir}/etc/ossec.conf
  chown root:ossec %{_localstatedir}/etc/ossec.conf
  chmod 0640 %{_localstatedir}/etc/ossec.conf


  ETC_DECODERS="%{_localstatedir}/etc/decoders"
  ETC_RULES="%{_localstatedir}/etc/rules"

  # Moving local_decoder
  if [ -f "%{_localstatedir}/etc/local_decoder.xml" ]; then
    if [ -s "%{_localstatedir}/etc/local_decoder.xml" ]; then
      mv "%{_localstatedir}/etc/local_decoder.xml" $ETC_DECODERS
    else
      # it is empty
      rm -f "%{_localstatedir}/etc/local_decoder.xml"
    fi
  fi

  # Moving local_rules
  if [ -f "%{_localstatedir}/rules/local_rules.xml" ]; then
    mv "%{_localstatedir}/rules/local_rules.xml" $ETC_RULES
  fi

  # Creating backup directory
  if [ -d "%{_localstatedir}/etc/wazuh_decoders" ]; then
    BACKUP_RULESET="%{_localstatedir}/etc/backup_ruleset"
    mkdir $BACKUP_RULESET > /dev/null 2>&1
    chmod 750 $BACKUP_RULESET > /dev/null 2>&1
    chown root:ossec $BACKUP_RULESET > /dev/null 2>&1
    # Backup decoders: Wazuh v1.0.1 to v1.1.1
    old_decoders="ossec_decoders wazuh_decoders"
    for old_decoder in $old_decoders
    do
      if [ -d "%{_localstatedir}/etc/$old_decoder" ]; then
        mv "%{_localstatedir}/etc/$old_decoder" $BACKUP_RULESET
      fi
    done

    # Backup decoders: Wazuh v1.0 and OSSEC
    if [ -f "%{_localstatedir}/etc/decoder.xml" ]; then
      mv "%{_localstatedir}/etc/decoder.xml" $BACKUP_RULESET
    fi
    if [ -d "%{_localstatedir}/rules" ]; then
      # Backup rules: All versions
      mv "%{_localstatedir}/rules" $BACKUP_RULESET
    fi
  fi
  passlist="%{_localstatedir}/agentless/.passlist"

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


  touch %{_localstatedir}/logs/ossec.log
  touch %{_localstatedir}/logs/integrations.log
  touch %{_localstatedir}/logs/active-responses.log
  touch %{_localstatedir}/etc/client.keys

  chown ossec:ossec %{_localstatedir}/logs/ossec.log
  chown ossecm:ossec %{_localstatedir}/logs/integrations.log
  chown ossec:ossec %{_localstatedir}/logs/active-responses.log
  chown root:ossec %{_localstatedir}/etc/client.keys

  chmod 0660 %{_localstatedir}/logs/ossec.log
  chmod 0640 %{_localstatedir}/logs/integrations.log
  chmod 0660 %{_localstatedir}/logs/active-responses.log
  chmod 0640 %{_localstatedir}/etc/client.keys

  # Add default local_files to ossec.conf
  %{_localstatedir}/tmp/add_localfiles.sh >>  %{_localstatedir}/etc/ossec.conf
   /sbin/chkconfig --add wazuh-manager
   /sbin/chkconfig wazuh-manager on

fi

  # Generation auto-signed certificate if not exists
  if type openssl >/dev/null 2>&1 && [ ! -f "%{_localstatedir}/etc/sslmanager.key" ] && [ ! -f "%{_localstatedir}/etc/sslmanager.cert" ]; then
      echo "Generating self-signed certificate for ossec-authd"
      openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout %{_localstatedir}/etc/sslmanager.key -out %{_localstatedir}/etc/sslmanager.cert
      chmod 640 %{_localstatedir}/etc/sslmanager.key
      chmod 640 %{_localstatedir}/etc/sslmanager.cert
  fi

  if [ -f "%{_localstatedir}/etc/shared/agent.conf" ]; then
    mv "%{_localstatedir}/etc/shared/agent.conf" "%{_localstatedir}/etc/shared/default/agent.conf"
    chmod 0660 %{_localstatedir}/etc/shared/default/agent.conf
    chown root:ossec %{_localstatedir}/etc/shared/default/agent.conf
  fi

rm %{_localstatedir}/etc/shared/ar.conf  >/dev/null 2>&1 || true
rm %{_localstatedir}/etc/shared/merged.mg  >/dev/null 2>&1 || true

touch %{_localstatedir}/logs/ossec.json
chown ossec:ossec %{_localstatedir}/logs/ossec.json
chmod 0660 %{_localstatedir}/logs/ossec.json

touch %{_localstatedir}/logs/cluster.log
chown ossec:ossec %{_localstatedir}/logs/cluster.log
chmod 0660 %{_localstatedir}/logs/cluster.log

chown root:ossec %{_localstatedir}/framework/wazuh/cluster.json
# Temporal fix for cluster.json permissions
chmod 640 %{_localstatedir}/framework/wazuh/cluster.json



rm -f %{_localstatedir}/tmp/add_localfiles.sh
rm -rf %{_localstatedir}/tmp/src
rm -rf %{_localstatedir}/tmp/etc
ln -sf %{_sysconfdir}/ossec-init.conf %{_localstatedir}/etc/ossec-init.conf

chmod 640 %{_sysconfdir}/ossec-init.conf
chown root:ossec %{_sysconfdir}/ossec-init.conf

if [ $1 = 2 ]; then
  if [ -f %{_localstatedir}/etc/ossec.bck ]; then
      mv %{_localstatedir}/etc/ossec.bck %{_localstatedir}/etc/ossec.conf
  fi
fi

# Agent info change between 2.1.1 and 3.0.0
chmod 0660 %{_localstatedir}/queue/agent-info/* 2>/dev/null || true
chown ossecr:ossec %{_localstatedir}/queue/agent-info/* 2>/dev/null || true

touch %{_localstatedir}/etc/shared/default/*

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl stop wazuh-manager
  systemctl enable wazuh-manager > /dev/null 2>&1
fi

if %{_localstatedir}/bin/ossec-logtest 2>/dev/null ; then
  /sbin/service wazuh-manager restart 2>&1
else
  echo "================================================================================================================"
  echo "Something in your actual rules configuration is wrong, please review your configuration and restart the service."
  echo "================================================================================================================"
fi

if [ ! -f %{_localstatedir}/queue/agents-timestamp ]; then
  touch %{_localstatedir}/queue/agents-timestamp
fi
chmod 600 %{_localstatedir}/queue/agents-timestamp
chown root:ossec %{_localstatedir}/queue/agents-timestamp

%preun

if [ $1 = 0 ]; then

  /sbin/service wazuh-manager stop || :

  /sbin/chkconfig wazuh-manager off
  /sbin/chkconfig --del wazuh-manager

  /sbin/service wazuh-manager stop || :

  rm -f %{_localstatedir}/etc/localtime || :
fi

%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/etc
 chown root:ossec %{_localstatedir}/etc/localtime
 chmod 0640 %{_localstatedir}/etc/localtime

%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%doc BUGS CONFIG CONTRIBUTORS INSTALL LICENSE README.md CHANGELOG
%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%attr(750,root,ossec) %dir %{_localstatedir}
%attr(750,root,ossec) %dir %{_localstatedir}/active-response
%attr(750,root,ossec) %dir %{_localstatedir}/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/agentless
%attr(750,root,ossec) %dir %{_localstatedir}/backup
%attr(750,ossec,ossec) %dir %{_localstatedir}/backup/agents
%attr(750,ossec,ossec) %dir %{_localstatedir}/backup/groups
%attr(750,root,ossec) %dir %{_localstatedir}/backup/shared
%attr(750,root,ossec) %dir %{_localstatedir}/bin
%attr(770,ossec,ossec) %dir %{_localstatedir}/etc
%attr(770,root,ossec) %dir %{_localstatedir}/etc/decoders
%attr(770,root,ossec) %dir %{_localstatedir}/etc/lists
%attr(770,root,ossec) %dir %{_localstatedir}/etc/lists/amazon
%attr(770,root,ossec) %dir %{_localstatedir}/etc/shared
%attr(770,root,ossec) %dir %{_localstatedir}/etc/shared/default
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
%attr(770,root,ossec) %dir %{_localstatedir}/queue/agent-groups
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/agentless
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/agents
%attr(770,ossec,ossec) %dir %{_localstatedir}/queue/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/db
%attr(750,ossec,ossec) %dir %{_localstatedir}/queue/fts
%attr(770,ossecr,ossec) %dir %{_localstatedir}/queue/rids
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
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/aws
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/vuls
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/vuls/go
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/oscap
%attr(750,root,ossec) %dir %{_localstatedir}/wodles/oscap/content

%attr(640,root,ossec) %{_localstatedir}/framework/lib/*
%attr(640,root,ossec) %{_localstatedir}/framework/wazuh/*
%attr(750,root,ossec) %{_localstatedir}/integrations/*
%attr(750,root,root) %{_localstatedir}/bin/*
%attr(750,root,ossec) %{_localstatedir}/bin/agent_groups
%attr(750,root,ossec) %{_localstatedir}/bin/agent_upgrade
%attr(750,root,ossec) %{_localstatedir}/bin/cluster_control
%attr(750,root,ossec) %{_localstatedir}/bin/wazuh-clusterd-internal
%attr(750,root,ossec) %{_localstatedir}/bin/wazuh-clusterd
%{_initrddir}/*
%attr(750,root,ossec) %{_localstatedir}/active-response/bin/*
%attr(640,root,ossec) %{_localstatedir}/etc/ossec.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/decoders/local_decoder.xml
%attr(640,root,ossec) %{_localstatedir}/etc/internal_options*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/local_internal_options.conf
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/rules/local_rules.xml
%attr(660,root,ossec) %config(noreplace) %{_localstatedir}/etc/shared/default/*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/etc/lists/audit-*
%attr(660,root,ossec) %config(noreplace) %{_localstatedir}/etc/lists/amazon/*
%attr(660,root,ossec) %{_localstatedir}/etc/rootcheck/*.txt
%attr(640,root,ossec) %{_localstatedir}/ruleset/VERSION
%attr(640,root,ossec) %{_localstatedir}/ruleset/rules/*
%attr(640,root,ossec) %{_localstatedir}/ruleset/decoders/*
%attr(750,root,ossec) %{_localstatedir}/wodles/aws/*
%attr(750,root,ossec) %{_localstatedir}/wodles/vuls/*
%attr(750,root,ossec) %{_localstatedir}/wodles/oscap/oscap.*
%attr(750,root,ossec) %{_localstatedir}/wodles/oscap/template*
%attr(640,root,ossec) %{_localstatedir}/wodles/oscap/content/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/src/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/generic/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/centos/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/fedora/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/tmp/etc/templates/config/rhel/*

/usr/share/wazuh-manager/scripts/tmp/add_localfiles.sh
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/alerts.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/ar-commands.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/ar-definitions.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/auth.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/cluster.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/global-ar.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/global.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/header-comments.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-commands.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/apache-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/audit-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/ossec-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/pgsql-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/snort-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/localfile-logs/syslog-logs.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/logging.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/remote-secure.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/remote-syslog.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/rootcheck.agent.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/rootcheck.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/rules.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/syscheck.agent.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/syscheck.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/wodle-ciscat.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/wodle-syscollector.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/generic/wodle-vulnerability-detector.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/5/rootcheck.agent.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/5/rootcheck.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/5/wodle-syscollector.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/6/openscap.files
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/6/rootcheck.agent.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/6/rootcheck.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/6/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/7/openscap.files
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/7/rootcheck.agent.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/7/rootcheck.manager.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/centos/7/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/fedora/24/openscap.files
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/fedora/24/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/5/rootcheck.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/6/openscap.files
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/6/rootcheck.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/6/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/7/openscap.files
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/7/rootcheck.template
/usr/share/wazuh-manager/scripts/tmp/etc/templates/config/rhel/7/wodle-openscap.template
/usr/share/wazuh-manager/scripts/tmp/gen_ossec.sh
/usr/share/wazuh-manager/scripts/tmp/src/LOCATION
/usr/share/wazuh-manager/scripts/tmp/src/REVISION
/usr/share/wazuh-manager/scripts/tmp/src/VERSION
/usr/share/wazuh-manager/scripts/tmp/src/init/adduser.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/darwin-addusers.pl
/usr/share/wazuh-manager/scripts/tmp/src/init/darwin-init.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/dist-detect.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/functions.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/fw-check.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/init.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/inst-functions.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/language.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-client.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-aix.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-debian.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-gentoo.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-hpux.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-rh.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-solaris.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids-suse.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-hids.init
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-local.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/ossec-server.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/osx105-addusers.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/pkg_installer.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/replace_manager_ip.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/shared.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/template-select.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/update.sh
/usr/share/wazuh-manager/scripts/tmp/src/init/wazuh/database.py
/usr/share/wazuh-manager/scripts/tmp/src/init/wazuh/deprecated_ruleset.txt
/usr/share/wazuh-manager/scripts/tmp/src/init/wazuh/upgrade.py
/usr/share/wazuh-manager/scripts/tmp/src/init/wazuh/wazuh.sh
%if %{_debugenabled} == "yes"
/usr/lib/debug/%{_localstatedir}/*
/usr/src/debug/%{name}-%{version}/*
%endif


%changelog
* Wed Feb 21 2018 support <support@wazuh.com> - 3.2.1
- More info: https://documentation.wazuh.com/current/release-notes/
* Wed Feb 07 2018 support <support@wazuh.com> - 3.2.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Mon Dec 19 2017 support <support@wazuh.com> - 3.1.0
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
