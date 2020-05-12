Summary:     Wazuh API is an open source RESTful API to interact with Wazuh from your own application or with a simple web browser or tools like cURL
Name:        wazuh-api
Version:     3.7.1
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

Requires: nodejs >= 4.6
Requires: wazuh-manager = 3.7.1
BuildRequires: nodejs >= 4.6
ExclusiveOS: linux

%description
Wazuh API is an open source RESTful API to interact with Wazuh
from your own application or with a simple web browser or tools like cURL

%prep
%setup -q

# Install nodejs dependencies
npm install --production

#Create ossec group
if ! id -g ossec > /dev/null 2>&1; then
  groupadd -r ossec
fi

#Create ossec user. Assign it to ossec group.
if ! id -u ossec > /dev/null 2>&1; then
  useradd -g ossec -G ossec       \
        -d %{_localstatedir}/ossec \
        -r -s /sbin/nologin ossec
fi

%install
# Clean BUILDROOT
rm -fr %{buildroot}

# Create the directories needed to install the wazuh-api
mkdir -p %{_localstatedir}/ossec/{framework,logs}
echo 'DIRECTORY="%{_localstatedir}/ossec"' > /etc/ossec-init.conf
# Install the wazuh-api
./install_api.sh --no-service
# Remove the framework directory
rmdir %{_localstatedir}/ossec/framework

# Add the files for the package
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api
cp -pr %{_localstatedir}/ossec/* ${RPM_BUILD_ROOT}%{_localstatedir}/ossec/
cp CHANGELOG.md CHANGELOG

exit 0
%pre

# Upgrading
if [ $1 = 2 ]; then
  # Stop services
  if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
    systemctl stop wazuh-api.service > /dev/null
  elif [ -x /etc/rc.d/init.d/wazuh-api ] ; then
    /etc/rc.d/init.d/wazuh-api stop > /dev/null
  elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
    /etc/init.d/wazuh-api stop > /dev/null
  fi
fi

# Installing
if [ $1 = 1 ]; then

  API_PATH="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api"
  API_PATH_BACKUP="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/~api"

  if [ -e ${API_PATH} ]; then

    if [ -e ${API_PATH_BACKUP} ]; then
      rm -rf ${API_PATH_BACKUP}
    fi

    rm -f %{_localstatedir}/ossec/api/configuration/auth/htpasswd
    cp -rLfp ${API_PATH} ${API_PATH_BACKUP}
  fi
fi

%post

# Install daemon. It will load new daemon (SysV and Systemctl) and start the service.
%{_localstatedir}/ossec/api/scripts/install_daemon.sh > /dev/null

API_PATH="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/api"
API_PATH_BACKUP="${RPM_BUILD_ROOT}%{_localstatedir}/ossec/~api"

if [ -d ${API_PATH_BACKUP} ]; then
  cp -rfnp ${API_PATH_BACKUP}/configuration ${API_PATH_BACKUP_BACKUP}/configuration
  rm -rf ${API_PATH_BACKUP}
fi

# Verify if Python is installed and its version
if python -V >/dev/null 2>&1; then
 python_version=$(python -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' | cut -c1-3)
 if [ ! $python_version == '2.7' ]; then
    echo "Warning: Minimal supported version is 2.7."
 fi
else
 echo "Warning: You need Python 2.7 or greater."
fi

%preun

if [ $1 = 0 ]; then
  if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
    systemctl stop wazuh-api.service > /dev/null
    systemctl disable wazuh-api.service > /dev/null
    rm -f /etc/systemd/system/wazuh-api.service
  fi

  if [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
    /etc/init.d/wazuh-api stop > /dev/null
    chkconfig wazuh-api off
    chkconfig --del wazuh-api
    rm -f /etc/rc.d/init.d/wazuh-api || true
  fi
fi

%posttrans

# Restart the Wazuh API service in case the installation was trigger as dependency
if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
  systemctl start wazuh-api.service > /dev/null
elif [ -x /etc/rc.d/init.d/wazuh-api ] ; then
  /etc/rc.d/init.d/wazuh-api start > /dev/null
elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
  /etc/init.d/wazuh-api start > /dev/null
else
  echo "Error: Wazuh API could not restart"
fi

%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%doc CHANGELOG
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api
%attr(750, root, ossec) %{_localstatedir}/ossec/api/app.js
%attr(640, root, ossec) %{_localstatedir}/ossec/api/package.json
%attr(644, root, root) %{_localstatedir}/ossec/api/package-lock.json
%dir %attr(750, root, ossec) %config(noreplace) %{_localstatedir}/ossec/api/configuration
%attr(740, root, ossec) %config(noreplace) %{_localstatedir}/ossec/api/configuration/config.js
%attr(750, root, root) %{_localstatedir}/ossec/api/configuration/preloaded_vars.conf
%dir %attr(750, root, root) %config(noreplace) %{_localstatedir}/ossec/api/configuration/auth
%{_localstatedir}/ossec/api/configuration/auth/htpasswd
%attr(660, root, root) %config(noreplace) %{_localstatedir}/ossec/api/configuration/auth/user
%dir %attr(750, root, root) %config(noreplace) %{_localstatedir}/ossec/api/configuration/ssl
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/controllers
%attr(750, root, ossec) %{_localstatedir}/ossec/api/controllers/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/examples
%attr(750, root, ossec) %{_localstatedir}/ossec/api/examples/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/helpers
%attr(750, root, ossec) %{_localstatedir}/ossec/api/helpers/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/models
%attr(750, root, ossec) %{_localstatedir}/ossec/api/models/*
%dir %attr(750, root, root) %{_localstatedir}/ossec/api/scripts
%attr(750, root, root) %{_localstatedir}/ossec/api/scripts/*.sh
%attr(640, root, root) %{_localstatedir}/ossec/api/scripts/wazuh-api
%attr(640, root, root) %{_localstatedir}/ossec/api/scripts/wazuh-api.service
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/node_modules
%attr(750, ossec, ossec) %{_localstatedir}/ossec/api/node_modules/*
%dir %attr(750, root, ossec) %{_localstatedir}/ossec/api/node_modules/.bin
%{_localstatedir}/ossec/api/node_modules/.bin/*
%dir %attr(750, ossec, ossec) %{_localstatedir}/ossec/logs/api
%attr(660, ossec, ossec) %ghost %{_localstatedir}/ossec/logs/api.log

%changelog
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
* Mon Nov 07 2017 support <support@wazuh.com> - 3.0.0
- More info: https://documentation.wazuh.com/current/release-notes/
* Fri May 26 2017 support <support@wazuh.com> - 2.0.1
- Issue when basic-auth is disabled.
- Regex for latest version in install_api.sh
- Wrong scan dates for syscheck and rootcheck.
- IP value always must be lowercase.
* Fri Sep 16 2016 Jose Luis Ruiz <jose@wazuh.com> - 2.0
- First rpm.
