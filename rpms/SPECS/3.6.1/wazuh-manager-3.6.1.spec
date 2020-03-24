Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-manager
Version:     3.6.1
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
%if 0%{?el} >= 6 || 0%{?rhel} >= 6
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils-python curl
%else
BuildRequires: coreutils glibc-devel automake autoconf libtool policycoreutils curl
%endif

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

./gen_ossec.sh conf manager centos %rhel %{_localstatedir}/ossec > etc/ossec-server.conf
./gen_ossec.sh init manager %{_localstatedir}/ossec > ossec-init.conf

pushd src
# Rebuild for server
make clean

%if 0%{?el} >= 6 || 0%{?rhel} >= 6
    make deps
    make -j%{_threads} TARGET=server USE_SELINUX=yes USE_FRAMEWORK_LIB=yes PREFIX=%{_localstatedir}/ossec
%else
    make deps RESOURCES_URL=http://packages.wazuh.com/deps/3.5
    make -j%{_threads} TARGET=server USE_AUDIT=no USE_SELINUX=yes USE_FRAMEWORK_LIB=yes USE_EXEC_ENVIRON=no PREFIX=%{_localstatedir}/ossec
%endif

popd

%install
# Clean BUILDROOT
rm -fr %{buildroot}

mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/backup/{agents,groups,shared}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/{decoders,lists,rules,shared,rootcheck,init.d}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists/amazon
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared/default
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/{lib,wazuh}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/wazuh/cluster
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/integrations
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lib
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/logs/{alerts,archives,cluster,firewall,ossec}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/queue/{agent-groups,agent-info,agentless,agents,alerts,cluster,db,diff,fts,ossec,rids,rootcheck,syscheck,vulnerabilities}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/{decoders,rules}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/.ssh
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/stats
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/{db,run,selinux,upgrade,wodles}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/db/agents
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/download
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/wodles
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/aws

# Templates for initscript
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/centos
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/fedora
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/rhel

cp -rp  etc/templates/config/generic/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/generic
# Copy scap templates
cp -rp  etc/templates/config/centos/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/centos
cp -rp  etc/templates/config/fedora/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/fedora
cp -rp  etc/templates/config/rhel/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/etc/templates/config/rhel

install -m 0640 ossec-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install -m 0750 active-response/firewalls/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0750 active-response/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0750 active-response/*.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/active-response/bin
install -m 0550 src/agentlessd/scripts/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/agentless
install -m 0550 src/agent_control ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 framework/scripts/agent_groups.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/agent_groups
install -m 0550 framework/scripts/agent_upgrade.py  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/agent_upgrade
install -m 0550 framework/scripts/cluster_control.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/cluster_control
install -m 0550 framework/scripts/wazuh-clusterd.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/wazuh-clusterd
install -m 0660 framework/libsqlite3.so.0 ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/lib

install -m 0550 src/clear_stats ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/manage_agents ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-agentlessd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-analysisd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-authd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin

# Install Wazuh Lib
install -m 0750 src/libwazuhext.so ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/lib

cp -pr src/init/ossec-server.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/ossec-control
install -m 0550 src/ossec-csyslogd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-dbd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-execd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-integratord ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-logcollector ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/ossec-logtest ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
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
install -m 0750 src/update/ruleset/update_ruleset ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin/update_ruleset
install -m 0550 src/verify-agent-conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 contrib/util.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0750 src/wazuh-db ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0550 src/wazuh-modulesd ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/bin
install -m 0440 etc/local_decoder.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/decoders
install -m 0640 etc/internal_options* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0660 etc/lists/amazon/aws-eventnames ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-eventnames.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-sources ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists/amazon
install -m 0660 etc/lists/amazon/aws-sources.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists/amazon
install -m 0640 etc/lists/audit-keys ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists
install -m 0640 etc/lists/audit-keys.cdb ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/lists
install -m 0640 etc/local_internal_options.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc
install -m 0660 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/rootcheck
install -m 0640 etc/local_rules.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/rules
install -m 0640 etc/agent.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared/default
install -m 0660 src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/shared/default
install -m 0640 framework/wazuh/*.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/wazuh
install -m 0640 framework/wazuh/cluster/*.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/wazuh/cluster
install -m 0640 framework/wazuh/cluster/cluster.json ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/framework/wazuh/cluster

install -m 0640 etc/rules/*xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/rules
install -m 0640 etc/decoders/*.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/decoders
install -m 0440 src/update/ruleset/RULESET_VERSION  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/ruleset/VERSION
install -m 0750 integrations/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/integrations
# AWS wodle
install -m 0750 wodles/aws/aws-s3.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/aws/aws-s3
install -m 0750 wodles/oscap/oscap.py ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0750 wodles/oscap/template_oval.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0750 wodles/oscap/template_xccdf.xsl ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap
install -m 0640 wodles/oscap/content/cve-redhat-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-rhel-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-centos-7-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/cve-redhat-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-rhel-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-centos-6-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content
install -m 0640 wodles/oscap/content/ssg-fedora-24-ds.xml ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/wodles/oscap/content

install -m 0755 src/init/ossec-hids-rh.init ${RPM_BUILD_ROOT}%{_initrddir}/wazuh-manager

# Temporal files for gent_ossec
install -m 0640 src/init/inst-functions.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/template-select.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/init/shared.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src/init
install -m 0640 src/LOCATION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 src/VERSION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 src/REVISION ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp/src
install -m 0640 add_localfiles.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/tmp

# SELinux file
install -m 0640 src/selinux/wazuh.pp ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/var/selinux

cp CHANGELOG.md CHANGELOG

cp -pr etc/ossec-server.conf ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/etc/ossec.conf

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

# Systemd files
mkdir -p ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/systemd
cp -r src/systemd/*  ${RPM_BUILD_ROOT}/usr/share/wazuh-manager/scripts/tmp/src/systemd

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
if ps aux | grep %{_localstatedir}/ossec/bin/ossec-authd | grep -v grep > /dev/null 2>&1; then
   kill `ps -ef | grep '%{_localstatedir}/ossec/bin/ossec-authd' | grep -v grep | awk '{print $2}'` > /dev/null 2>&1
fi

# Ensure that the wazuh-manager is stopped
if [ -d %{_localstatedir}/ossec ] && [ -f %{_localstatedir}/ossec/bin/ossec-control ] ; then
  %{_localstatedir}/ossec/bin/ossec-control stop
fi

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

if [ -d ${DIR}/var/db/agents ]; then
  rm -f ${DIR}/var/db/agents/*
fi

# Remove existing SQLite databases
rm -f %{_localstatedir}/ossec/var/db/global.db* || true
rm -f %{_localstatedir}/ossec/var/db/cluster.db* || true
rm -f %{_localstatedir}/ossec/var/db/.profile.db* || true
rm -f %{_localstatedir}/ossec/var/db/agents/* || true

# Remove existing SQLite databases for Wazuh DB
rm -f %{_localstatedir}/ossec/queue/db/*.db*
rm -f %{_localstatedir}/ossec/queue/db/.template.db

# Back up the cluster.json >= 3.2.3
if [ -d %{_localstatedir}/ossec/framework ]; then
    if [ -f %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json ]; then
        cp %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json /tmp/cluster.json
        rm -f %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json
    fi
fi

# Backup /etc/shared/default/agent.conf file
if [ -f %{_localstatedir}/ossec/etc/shared/default/agent.conf ]; then
  cp -p %{_localstatedir}/ossec/etc/shared/default/agent.conf /tmp/agent.conf
fi

# Delete old service
if [ -f /etc/init.d/ossec ]; then
  rm /etc/init.d/ossec
fi
if [ $1 = 1 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.conf ]; then
    echo "====================================================================================="
    echo "= Backup from your ossec.conf has been created at %{_localstatedir}/ossec/etc/ossec.conf.rpmorig ="
    echo "= Please verify your ossec.conf configuration at %{_localstatedir}/ossec/etc/ossec.conf          ="
    echo "====================================================================================="
    mv %{_localstatedir}/ossec/etc/ossec.conf %{_localstatedir}/ossec/etc/ossec.conf.rpmorig
  fi
fi
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

if [ $1 = 1 ]; then
  # Generating osse.conf file
  . /usr/share/wazuh-manager/scripts/tmp/src/init/dist-detect.sh
  /usr/share/wazuh-manager/scripts/tmp/gen_ossec.sh conf manager ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} %{_localstatedir}/ossec > %{_localstatedir}/ossec/etc/ossec.conf
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
  chown ossec:ossec %{_localstatedir}/ossec/etc/client.keys

  chmod 0660 %{_localstatedir}/ossec/logs/ossec.log
  chmod 0640 %{_localstatedir}/ossec/logs/integrations.log
  chmod 0660 %{_localstatedir}/ossec/logs/active-responses.log
  chmod 0640 %{_localstatedir}/ossec/etc/client.keys

  # Add default local_files to ossec.conf
  %{_localstatedir}/ossec/tmp/add_localfiles.sh %{_localstatedir}/ossec >> %{_localstatedir}/ossec/etc/ossec.conf
   /sbin/chkconfig --add wazuh-manager
   /sbin/chkconfig wazuh-manager on

fi

# "Restore the old cluster.json"
if [ -f /tmp/cluster.json ]; then
    mv /tmp/cluster.json %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json.old
    chown root:ossec %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json.old
    chmod 640 %{_localstatedir}/ossec/framework/wazuh/cluster/cluster.json.old
fi

# Restore the agent.conf
if [ -f /tmp/agent.conf ]; then
  cp -rp /tmp/agent.conf %{_localstatedir}/ossec/etc/shared/default/agent.conf
  rm /tmp/agent.conf
  chown ossec:ossec %{_localstatedir}/ossec/etc/shared/default/agent.conf
  chmod 660 %{_localstatedir}/ossec/etc/shared/default/agent.conf
fi

if [ -f "%{_localstatedir}/ossec/etc/shared/agent.conf" ]; then
mv "%{_localstatedir}/ossec/etc/shared/agent.conf" "%{_localstatedir}/ossec/etc/shared/default/agent.conf"
chmod 0660 %{_localstatedir}/ossec/etc/shared/default/agent.conf
chown ossec:ossec %{_localstatedir}/ossec/etc/shared/default/agent.conf
fi

# Generation auto-signed certificate if not exists
if type openssl >/dev/null 2>&1 && [ ! -f "%{_localstatedir}/ossec/etc/sslmanager.key" ] && [ ! -f "%{_localstatedir}/ossec/etc/sslmanager.cert" ]; then
  echo "Generating self-signed certificate for ossec-authd"
  openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout %{_localstatedir}/ossec/etc/sslmanager.key -out %{_localstatedir}/ossec/etc/sslmanager.cert
  chmod 640 %{_localstatedir}/ossec/etc/sslmanager.key
  chmod 640 %{_localstatedir}/ossec/etc/sslmanager.cert
fi

rm %{_localstatedir}/ossec/etc/shared/ar.conf  >/dev/null 2>&1 || true
rm %{_localstatedir}/ossec/etc/shared/merged.mg  >/dev/null 2>&1 || true

touch %{_localstatedir}/ossec/logs/ossec.json
chown ossec:ossec %{_localstatedir}/ossec/logs/ossec.json
chmod 0660 %{_localstatedir}/ossec/logs/ossec.json

if [ -f %{_localstatedir}/ossec/logs/cluster.log ]; then
    chown ossec:ossec %{_localstatedir}/ossec/logs/cluster.log
    chmod 0660 %{_localstatedir}/ossec/logs/cluster.log
fi

chown -R ossec:ossec %{_localstatedir}/ossec/etc/client.keys
chown -R ossec:ossec %{_localstatedir}/ossec/etc/lists/*
chown -R ossec:ossec %{_localstatedir}/ossec/etc/decoders/*
chown -R ossec:ossec %{_localstatedir}/ossec/etc/rules/*
chown -R ossec:ossec %{_localstatedir}/ossec/etc/shared/*

rm -f %{_localstatedir}/ossec/tmp/add_localfiles.sh
rm -rf %{_localstatedir}/ossec/tmp/src
rm -rf %{_localstatedir}/ossec/tmp/etc
ln -sf %{_sysconfdir}/ossec-init.conf %{_localstatedir}/ossec/etc/ossec-init.conf

chmod 640 %{_sysconfdir}/ossec-init.conf
chown root:ossec %{_sysconfdir}/ossec-init.conf

if [ $1 = 2 ]; then
  if [ -f %{_localstatedir}/ossec/etc/ossec.bck ]; then
      mv %{_localstatedir}/ossec/etc/ossec.bck %{_localstatedir}/ossec/etc/ossec.conf
  fi
fi

# Agent info change between 2.1.1 and 3.0.0
chmod 0660 %{_localstatedir}/ossec/queue/agent-info/* 2>/dev/null || true
chown ossecr:ossec %{_localstatedir}/ossec/queue/agent-info/* 2>/dev/null || true

# If systemd is installed, add the wazuh-manager.service file to systemd files directory
if [ -d /run/systemd/system ]; then
  install -m 644 /usr/share/wazuh-manager/scripts/tmp/src/systemd/wazuh-manager.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl stop wazuh-manager
  systemctl enable wazuh-manager > /dev/null 2>&1
fi

# The check for SELinux is not executed in the legacy OS.
add_selinux="yes"
if [ "${DIST_NAME}" == "centos" -a "${DIST_VER}" == "5" ] || [ "${DIST_NAME}" == "rhel" -a "${DIST_VER}" == "5" ] || [ "${DIST_NAME}" == "suse" -a "${DIST_VER}" == "11" ] ; then
  add_selinux="no"
fi

# Check if SELinux is installed and enabled
if [ ${add_selinux} == "yes" ]; then
  if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
    if [ $(getenforce) !=  "Disabled" ]; then
      if ! (semodule -l | grep wazuh > /dev/null); then
        echo "Installing Wazuh policy for SELinux."
        semodule -i %{_localstatedir}/ossec/var/selinux/wazuh.pp
        semodule -e wazuh
      else
        echo "Skipping installation of Wazuh policy for SELinux: module already installed."
      fi
    else
      echo "SELinux is disabled. Not adding Wazuh policy."
    fi
  else
    echo "SELinux is not installed. Not adding Wazuh policy."
  fi
elif [ ${add_selinux} == "no" ]; then
  # SELINUX Policy for CentOS 5 and RHEL 5 to use the Wazuh Lib
  if [ "${DIST_NAME}" != "suse" ]; then
    if command -v getenforce > /dev/null 2>&1; then
      if [ $(getenforce) !=  "Disabled" ]; then
        chcon -t textrel_shlib_t  %{_localstatedir}/ossec/lib/libwazuhext.so
      fi
    fi
  fi
fi

if %{_localstatedir}/ossec/bin/ossec-logtest 2>/dev/null ; then
  /sbin/service wazuh-manager restart 2>&1
else
  echo "================================================================================================================"
  echo "Something in your actual rules configuration is wrong, please review your configuration and restart the service."
  echo "================================================================================================================"
fi

if [ ! -f %{_localstatedir}/ossec/queue/agents-timestamp ]; then
  touch %{_localstatedir}/ossec/queue/agents-timestamp
fi
chmod 600 %{_localstatedir}/ossec/queue/agents-timestamp
chown root:ossec %{_localstatedir}/ossec/queue/agents-timestamp

%preun

if [ $1 = 0 ]; then

  /sbin/service wazuh-manager stop || :
  %{_localstatedir}/ossec/bin/ossec-control stop 2>/dev/null
  /sbin/chkconfig wazuh-manager off
  /sbin/chkconfig --del wazuh-manager

  /sbin/service wazuh-manager stop || :

  # Check if Wazuh SELinux policy is installed
  if [ -r "/etc/centos-release" ]; then
    DIST_NAME="centos"
    DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' /etc/centos-release`

  elif [ -r "/etc/redhat-release" ]; then
    DIST_NAME="rhel"
    DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' /etc/redhat-release`
  elif [ -r "/etc/SuSE-release" ]; then
    DIST_NAME="suse"
    DIST_VER=`sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
  else
    DIST_NAME=""
    DIST_VER=""
  fi

  add_selinux="yes"
  if [ "${DIST_NAME}" == "centos" -a "${DIST_VER}" == "5" ] || [ "${DIST_NAME}" == "rhel" -a "${DIST_VER}" == "5" ] || [ "${DIST_NAME}" == "suse" -a "${DIST_VER}" == "11" ] ; then
    add_selinux="no"
  fi

  # If it is a valid system, remove the policy if it is installed
  if [ ${add_selinux} == "yes" ]; then
    if command -v getenforce > /dev/null 2>&1 && command -v semodule > /dev/null 2>&1; then
      if [ $(getenforce) !=  "Disabled" ]; then
        if (semodule -l | grep wazuh > /dev/null); then
          semodule -r wazuh
        fi
      fi
    fi
  fi

  rm -f %{_localstatedir}/ossec/etc/localtime || :
fi

%postun

# If the package is been uninstalled
if [ $1 == 0 ];then
  # Remove the ossec user if it exists
  if id -u ossec > /dev/null 2>&1; then
    userdel ossec
  fi
  # Remove the ossecr user if it exists
  if id -u ossecr > /dev/null 2>&1; then
    userdel ossecr
  fi
  # Remove the ossecm user if it exists
  if id -u ossecm > /dev/null 2>&1; then
    userdel ossecm
  fi
  # Remove the ossec group if it exists
  if id -g ossec > /dev/null 2>&1; then
    groupdel ossec
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
%doc BUGS CONFIG CONTRIBUTORS INSTALL LICENSE README.md CHANGELOG
%attr(640,root,ossec) %verify(not md5 size mtime) %{_sysconfdir}/ossec-init.conf
%attr(750,root,ossec) %dir %{_localstatedir}/ossec
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/active-response
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/active-response/bin
%attr(750,root,ossec) %{_localstatedir}/ossec/agentless
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/backup
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/backup/agents
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/backup/groups
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/backup/shared
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/bin
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/etc
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/decoders
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/lists
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/etc/lists/amazon
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/shared
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/etc/shared/default
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/rootcheck
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/etc/rules
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/framework
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/framework/lib
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/framework/wazuh
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/framework/wazuh/cluster
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/integrations
%attr(750,root,root) %dir %{_localstatedir}/ossec/lib
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/logs
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/archives
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/alerts
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/cluster
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/firewall
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/logs/ossec
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/queue
%attr(770,ossecr,ossec) %dir %{_localstatedir}/ossec/queue/agent-info
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/queue/agent-groups
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/agentless
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/agents
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/queue/alerts
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/queue/cluster
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/db
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/diff
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/fts
%attr(770,ossecr,ossec) %dir %{_localstatedir}/ossec/queue/rids
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/rootcheck
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/queue/syscheck
%attr(770,ossec,ossec) %dir %{_localstatedir}/ossec/queue/ossec
%attr(760,root,ossec) %dir %{_localstatedir}/ossec/queue/vulnerabilities
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset/decoders
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/ruleset/rules
%attr(700,root,ossec) %dir %{_localstatedir}/ossec/.ssh
%attr(750,ossec,ossec) %dir %{_localstatedir}/ossec/stats
%attr(1750,root,ossec) %dir %{_localstatedir}/ossec/tmp
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/var
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/db
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/db/agents
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/download
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/run
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/selinux
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/upgrade
%attr(770,root,ossec) %dir %{_localstatedir}/ossec/var/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/aws
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/wodles/oscap/content
%attr(640,root,ossec) %{_localstatedir}/ossec/framework/lib/*
%attr(640,root,ossec) %{_localstatedir}/ossec/framework/wazuh/*.py
%attr(640,root,ossec) %{_localstatedir}/ossec/framework/wazuh/cluster/*
%attr(750,root,ossec) %{_localstatedir}/ossec/integrations/*
%attr(750,root,root) %{_localstatedir}/ossec/bin/*
%attr(750,root,ossec) %{_localstatedir}/ossec/bin/agent_groups
%attr(750,root,ossec) %{_localstatedir}/ossec/bin/agent_upgrade
%attr(750,root,ossec) %{_localstatedir}/ossec/bin/cluster_control
%attr(750,root,ossec) %{_localstatedir}/ossec/bin/wazuh-clusterd
%{_initrddir}/*
%attr(750,root,ossec) %{_localstatedir}/ossec/active-response/bin/*
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/ossec.conf
%attr(640,ossec,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/decoders/local_decoder.xml
%attr(640,root,ossec) %{_localstatedir}/ossec/etc/internal_options*
%attr(640,root,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/local_internal_options.conf
%attr(640,ossec,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/rules/local_rules.xml
%attr(660,ossec,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/shared/default/*
%attr(640,ossec,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/audit-*
%attr(660,ossec,ossec) %config(noreplace) %{_localstatedir}/ossec/etc/lists/amazon/*
%attr(750,root,root) %{_localstatedir}/ossec/lib/*
%attr(660,root,ossec) %{_localstatedir}/ossec/etc/rootcheck/*.txt
%attr(640,root,ossec) %{_localstatedir}/ossec/ruleset/VERSION
%attr(640,root,ossec) %{_localstatedir}/ossec/ruleset/rules/*
%attr(640,root,ossec) %{_localstatedir}/ossec/ruleset/decoders/*
%attr(640,root,ossec) %{_localstatedir}/ossec/var/selinux/*
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/aws/*
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/oscap.*
%attr(750,root,ossec) %{_localstatedir}/ossec/wodles/oscap/template*
%attr(640,root,ossec) %{_localstatedir}/ossec/wodles/oscap/content/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/add_localfiles.sh
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/src/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/generic/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/centos/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/fedora/*
%attr(750,root,root) %config(missingok) %{_localstatedir}/ossec/tmp/etc/templates/config/rhel/*

/usr/share/wazuh-manager/scripts/tmp/*
%if %{_debugenabled} == "yes"
/usr/lib/debug/%{_localstatedir}/ossec/*
/usr/src/debug/%{name}-%{version}/*
%endif


%changelog
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
