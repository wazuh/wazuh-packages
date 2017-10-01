Summary:     Wazuh RESTful API
Name:        wazuh-api
Version:     2.1.1
Release:     1%{?dist}
License:     GPL
Group:       System Environment/Daemons
Source0:     https://github.com/wazuh/API/archive/%{name}-%{version}.tar.gz
Source1:     CHANGELOG
URL:         http://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      http://www.wazuh.com
Packager:    Wazuh, Inc <support@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(post):   /sbin/chkconfig
Requires(preun):  /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service

Requires: nodejs >= 4.6
Requires: wazuh-manager >= 1.2
BuildRequires: gcc-c++ make nodejs >= 4.6
ExclusiveOS: linux

%description
Wazuh API is an open source RESTful API to interact with Wazuh
from your own application or with a simple web browser or tools like cURL

%prep
%setup -q

mkdir -pm 700 framework/lib
LIB_PATH="framework/lib"
SONAME="libsqlite3.so.0"
SOURCE="framework/database/sqlite3.c"
gcc -pipe -O2 -shared -fPIC -o $LIB_PATH/$SONAME $SOURCE

npm install --production

%install
# Clean BUILDROOT
rm -fr %{buildroot}

mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
#Folders
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/{configuration,controllers,examples,framework,helpers,models,scripts}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/configuration/{auth,ssl}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/framework/{examples,lib,wazuh}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/node_modules
#Files
install -m 0400 package.json ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api
install -m 0500 app.js ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api
install -m 0500 configuration/config.js ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/configuration
install -m 0500 configuration/auth/user  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/configuration/auth
install -m 0500 controllers/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/controllers
install -m 0500 examples/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/examples
install -m 0500 framework/examples/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/framework/examples
install -m 0500 framework/wazuh/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/framework/wazuh
install -m 0500 helpers/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/helpers
install -m 0500 models/*  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/models
install -m 0500 scripts/configure_api.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/scripts
install -m 0500 scripts/install_daemon.sh ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/scripts
install -m 0400 scripts/wazuh-api ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/scripts
install -m 0400 scripts/wazuh-api.service  ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/scripts
install -m 0400 framework/lib/libsqlite3.so.0 ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/framework/lib

cp -r node_modules/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api/node_modules/

cp %{SOURCE1} CHANGELOG

exit 0
%pre

if [ $1 = 1 ]; then
  API_PATH="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api"
  API_PATH_BACKUP="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/~api"

  if [ -e ${API_PATH} ]; then
    if [ -e ${API_PATH_BACKUP} ]; then
        rm -rf ${API_PATH_BACKUP}
    fi

    cp -rLfp ${API_PATH} ${API_PATH_BACKUP}
    chown root:root ${API_PATH_BACKUP}

    ${API_OLD_VERSION}=`cat ${API_PATH_BACKUP}/package.json | grep "version\":" | grep -P "\d+(?:\.\d+){0,2}" -o`
    if [ "X${API_OLD_VERSION}" == "X1.3.0" ]; then
        rm -rf ${API_PATH}/configuration
        cp -rfp ${API_PATH_BACKUP}/configuration ${API_PATH}/configuration
    elif [ "X${API_OLD_VERSION}" == "X1.1" ] || [ "X${API_OLD_VERSION}" == "X1.2.0" ] || [ "X${API_OLD_VERSION}" == "X1.2.1" ]; then
        cp -rfp ${API_PATH_BACKUP}/ssl/htpasswd ${API_PATH}/configuration/auth/user
        cp -p ${API_PATH_BACKUP}/ssl/*.key $API_PATH_BACKUP/ssl/*.crt ${API_PATH}/configuration/ssl/
        chown -R root:root ${API_PATH}/configuration
        chmod -R 500 ${API_PATH}/configuration
        chmod u-x ${API_PATH}/configuration/ssl/*
    fi
  fi
fi

%post

if [ $1 = 1 ]; then
  /var/ossec/api/scripts/install_daemon.sh
  touch /var/ossec/logs/api.log
  chmod 660 /var/ossec/logs/api.log
  chown root:ossec /var/ossec/logs/api.log
  echo "Don't forget to run the configuration script after installation: /var/ossec/api/scripts/configure_api.sh"
fi
ln -sf /var/ossec/api/node_modules/htpasswd/bin/htpasswd /var/ossec/api/configuration/auth/htpasswd

#verify python version
if python -V >/dev/null 2>&1; then
   python_version=$(python -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' | cut -c1-3)
   if [ ! $python_version == '2.7' ]; then
      echo "Warning: Minimal supported version is 2.7"
   fi
else
   echo "Warning: You need python 2.7 or above"
fi

if ps axu | grep /var/ossec/api/app.js | grep -v grep; then
   if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
     systemctl restart wazuh-api.service
   fi
   if [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
     service wazuh-api restart
   fi
fi

%preun

if [ $1 = 0 ]; then
  if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
    systemctl stop wazuh-api.service
    systemctl disable wazuh-api.service
    rm -f /etc/systemd/system/wazuh-api.service
  fi

  if [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
    service wazuh-api stop
    chkconfig wazuh-api off
  fi
fi


%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%doc CHANGELOG
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api
%attr(750,root,root) %config(noreplace) %dir %{_localstatedir}/ossec/api/configuration
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/controllers
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/examples
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/framework
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/helpers
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/models
%attr(750,root,root) %dir %{_localstatedir}/ossec/api/scripts
%attr(750,root,root) %config(noreplace) %dir %{_localstatedir}/ossec/api/configuration/auth
%attr(750,root,root) %config(noreplace) %dir %{_localstatedir}/ossec/api/configuration/ssl
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/framework/examples
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/framework/wazuh
%attr(750,root,ossec) %dir %{_localstatedir}/ossec/api/node_modules
%attr(750,root,ossec) %{_localstatedir}/ossec/api/framework/lib

%attr(640,root,ossec) %{_localstatedir}/ossec/api/package.json
%attr(750,root,ossec) %{_localstatedir}/ossec/api/app.js
%attr(750,root,root) %config(noreplace) %{_localstatedir}/ossec/api/configuration/config.js
%attr(750,root,root) %config(noreplace) %{_localstatedir}/ossec/api/configuration/auth/user
%attr(750,root,ossec) %{_localstatedir}/ossec/api/controllers/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/examples/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/framework/examples/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/framework/wazuh/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/framework/lib/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/helpers/*
%attr(750,root,ossec) %{_localstatedir}/ossec/api/models/*
%attr(750,root,root) %{_localstatedir}/ossec/api/scripts/*.sh
%attr(640,root,root) %{_localstatedir}/ossec/api/scripts/wazuh-api
%attr(640,root,root) %{_localstatedir}/ossec/api/scripts/wazuh-api.service
%attr(750,ossec,ossec) %{_localstatedir}/ossec/api/node_modules/*
%changelog
* Fri May 26 2017 support <support@wazuh.com> - 2.0.1
- Issue when basic-auth is disabled.
- Regex for latest version in install_api.sh
- Wrong scan dates for syscheck and rootcheck.
- IP value always must be lowercase.
* Fri Sep 16 2016 Jose Luis Ruiz <jose@wazuh.com> - 2.0
- First rpm.
