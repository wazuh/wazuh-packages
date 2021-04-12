Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-wui
Version:     5.0.0
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
buildroot:   %{_tmppath}/%{name}-%{version}-%{release}-wazuh-wui-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Requires(pre):    /usr/sbin/groupadd /usr/sbin/useradd
Requires(post):   /sbin/chkconfig
Requires(preun):  /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service
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

curl https://d3g5vo6xdbdb9a.cloudfront.net/tarball/opendistroforelasticsearch-kibana/opendistroforelasticsearch-kibana-1.13.1-linux-x64.tar.gz -o opendistroforelasticsearch-kibana-1.13.1-linux-x64.tar.gz
groupadd wazuh-wui
useradd -g wazuh-wui wazuh-wui

%build

tar -xf opendistroforelasticsearch-kibana-1.13.1-linux-x64.tar.gz

%install
mkdir -p %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs
mkdir -p %{buildroot}/%{_localstatedir}/usr/share/wazuh-wui
mkdir -p %{buildroot}/%{_localstatedir}/etc/systemd/system
mkdir -p %{buildroot}/%{_localstatedir}/etc/init.d
mkdir -p %{buildroot}/%{_localstatedir}/etc/default


mv opendistroforelasticsearch-kibana/config/* %{buildroot}/%{_localstatedir}/etc/wazuh-wui
mv opendistroforelasticsearch-kibana/* %{buildroot}/%{_localstatedir}/usr/share/wazuh-wui

mv /tmp/config/wazuh-wui.yml %{buildroot}/%{_localstatedir}/etc/wazuh-wui/wazuh-wui.yml
rm -f %{buildroot}/%{_localstatedir}/etc/wazuh-wui/kibana.yml


cp /tmp/services/wazuh-wui.service %{buildroot}/%{_localstatedir}/etc/systemd/system/wazuh-wui.service 
cp /tmp/services/wazuh-wui %{buildroot}/%{_localstatedir}/etc/init.d/wazuh-wui
cp /tmp/services/default %{buildroot}/%{_localstatedir}/etc/default/wazuh-wui

chmod 644 %{buildroot}/%{_localstatedir}/etc/init.d/wazuh-wui
chmod 644 %{buildroot}/%{_localstatedir}/etc/systemd/system/wazuh-wui.service 
chmod 644 %{buildroot}/%{_localstatedir}/etc/default/wazuh-wui



cp /tmp/certs/wazuh-wui.pem %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs/wazuh-wui.pem
cp /tmp/certs/wazuh-wui-key.pem %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs/wazuh-wui-key.pem
cp /tmp/certs/root-ca.pem %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs/root-ca.pem

cp /tmp/certs/root-ca.pem %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs/root-ca.pem
chmod 644 %{buildroot}/%{_localstatedir}/etc/wazuh-wui/certs/*

find %{buildroot}/usr/share/wazuh-wui -exec chown wazuh-wui:wazuh-wui {} \;
find %{buildroot}/etc/wazuh-wui -exec chown wazuh-wui:wazuh-wui {} \;

chown wazuh-wui:wazuh-wui %{buildroot}/%{_localstatedir}/etc/systemd/system/wazuh-wui.service
chown wazuh-wui:wazuh-wui %{buildroot}/%{_localstatedir}/etc/init.d/wazuh-wui


cd %{buildroot}/%{_localstatedir}/usr/share/wazuh-wui
sudo -u wazuh-wui bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.4_7.10.2-1.zip

find %{buildroot}/usr/share/wazuh-wui/plugins/wazuh/ -exec chown wazuh-wui:wazuh-wui {} \;


%pre
# Create the wazuh-wui group if it doesn't exists
if command -v getent > /dev/null 2>&1 && ! getent group wazuh-wui > /dev/null 2>&1; then
  groupadd -r wazuh-wui
elif ! id -g wazuh-wui > /dev/null 2>&1; then
  groupadd -r wazuh-wui
fi
# Create the wazuh-wui user if it doesn't exists
if ! id -u wazuh-wui > /dev/null 2>&1; then
  useradd -g wazuh-wui -G wazuh-wui -d %{_localstatedir} -r -s /sbin/nologin wazuh-wui
fi

# Stop the services to upgrade the package
if [ $1 = 2 ]; then
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-agent > /dev/null 2>&1; then
    systemctl stop wazuh-wui.service > /dev/null 2>&1
    touch %{_localstatedir}/usr/share/wazuh-wui/wazuh-wui.restart
  # Check for SysV
  elif command -v service > /dev/null 2>&1 && service wazuh-wui status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
    service wazuh-wui stop > /dev/null 2>&1
    touch %{_localstatedir}/usr/share/wazuh-wui/wazuh-wui.restart
  fi
fi

%post
setcap 'cap_net_bind_service=+ep' /usr/share/wazuh-wui/node/bin/node

%preun
if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 && systemctl is-active --quiet wazuh-agent > /dev/null 2>&1; then
    systemctl stop wazuh-wui.service > /dev/null 2>&1
  # Check for SysV
elif command -v service > /dev/null 2>&1 && service wazuh-wui status 2>/dev/null | grep "is running" > /dev/null 2>&1; then
  service wazuh-wui stop > /dev/null 2>&1
fi
%postun

# If the package is been uninstalled
if [ $1 = 0 ];then
  # Remove the wazuh-wui user if it exists
  if id -u wazuh-wui > /dev/null 2>&1; then
    userdel wazuh-wui >/dev/null 2>&1
  fi
  # Remove the wazuh-wui group if it exists
  if command -v getent > /dev/null 2>&1 && getent group wazuh-wui > /dev/null 2>&1; then
    groupdel wazuh-wui >/dev/null 2>&1
  elif id -g wazuh-wui > /dev/null 2>&1; then
    groupdel wazuh-wui >/dev/null 2>&1
  fi
fi

# posttrans code is the last thing executed in a install/upgrade
%posttrans
if [ -f %{_localstatedir}/usr/share/wazuh-wui/wazuh-wui.restart ]; then
  rm -f %{_localstatedir}/usr/share/wazuh-wui/wazuh-wui.restart
  if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1 ; then
    systemctl restart wazuh-wui.service > /dev/null 2>&1
  elif command -v service > /dev/null 2>&1 && service wazuh-wui status 2>/dev/null | grep "running" > /dev/null 2>&1; then
    service wazuh-wui restart > /dev/null 2>&1
  fi
fi

%clean
rm -fr %{buildroot}

%files
%defattr(0644,wazuh-wui,wazuh-wui,0755)

%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/init.d/wazuh-wui"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/default/wazuh-wui"
%config(noreplace) %attr(0644, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/wazuh-wui/wazuh-wui.yml"
%dir %attr(0755, wazuh-wui, wazuh-wui) %{_localstatedir}/etc/wazuh-wui/certs
%config(noreplace) %attr(0644, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/wazuh-wui/certs/*"
"%{_localstatedir}/usr/share/wazuh-wui/"
%attr(0644, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/wazuh-wui/node.options"
%attr(0644, wazuh-wui, wazuh-wui) "%{_localstatedir}/etc/systemd/system/wazuh-wui.service"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/bin/kibana"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/bin/kibana-keystore"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/bin/kibana-plugin" 
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node/bin/node"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node/lib"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node/share/doc/node/lldbinit"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@babel/parser/bin/babel-parser.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/charts/node_modules/uuid/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/.ci/bin/check_paths_for_matches.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/aggregate.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/folder_check.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/folder_closed.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/folder_exclamation.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/folder_open.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/menu.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/ml_data_visualizer.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/pageSelect.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/pagesSelect.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/push.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/quote.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/reporter.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/securitySignal.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/securitySignalDetected.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/securitySignalResolved.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/timeline.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/lib/components/icon/assets/users.svg"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/eui/node_modules/uuid/dist/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/good/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/good/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/good/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/good/lib/monitor.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@elastic/good/lib/utils.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/boom/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/boom/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/boom/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/bourne/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/bourne/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/bourne/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/good-squeeze/LICENSE.md"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/good-squeeze/lib/index.js"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/good-squeeze/lib/safe-json.js"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/good-squeeze/lib/squeeze.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/applyToDefaults.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/assert.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/bench.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/block.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/clone.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/contain.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/deepEqual.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/error.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/escapeHeaderAttribute.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/escapeHtml.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/escapeJson.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/escapeRegex.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/flatten.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/ignore.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/intersect.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/isPromise.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/merge.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/once.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/reach.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/reachTemplate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/stringify.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/types.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/utils.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/lib/wait.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/hoek/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/lib/payload.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/lib/recorder.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/@hapi/wreck/lib/tap.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/JSONStream/bin.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/JSONStream/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/lib/charset.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/lib/encoding.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/lib/language.js"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/accept/lib/mediatype.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ajv/scripts/info"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ajv/scripts/prepare-tests"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ajv/scripts/publish-built-version"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ajv/scripts/travis-gh-pages"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ammo/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ammo/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ammo/package.json"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/arr-diff/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/arr-flatten/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/arr-flatten/README.md"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/array-unique/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/array-unique/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/atob/bin/atob.js"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/b64/lib/decoder.js"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/b64/lib/encoder.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/b64/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/README.md"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/node_modules/hoek/README.md"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/node_modules/hoek/lib/escape.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/boom/node_modules/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/bounce/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/bounce/README.md"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/bounce/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/lib/regex.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/lib/segment.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/call/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox-memory/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox-memory/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/lib/client.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/lib/pending.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/lib/policy.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/catbox/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/content/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/content/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/copy-to-clipboard/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cross-env/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cross-env/src/bin/cross-env-shell.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cross-env/src/bin/cross-env.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cryptiles/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cryptiles/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cryptiles/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/cryptiles/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/css-tree/data/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/del/node_modules/micromatch/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/lib/LICENSE-jsbn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/lib/ec.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/lib/sec.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ecc-jsbn/test.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elastic-apm-node/node_modules/semver/bin/semver.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/.ci/run-tests"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/client.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/loggers/file.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/loggers/stdio.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/loggers/stream.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/loggers/tracer.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/selectors/random.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/elasticsearch/src/lib/serializers/json.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/emojis-list/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/emojis-list/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/esprima/bin/esparse.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/esprima/bin/esvalidate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/glob-all/bin/glob-all"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/h2o2/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/handlebars/bin/handlebars"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/handlebars/print-script"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi-auth-cookie/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/README.md"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/auth.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/compression.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/config.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/core.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/cors.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/ext.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/handler.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/headers.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/methods.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/request.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/response.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/route.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/security.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/server.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/streams.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/toolkit.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/transmit.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hapi/lib/validation.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/heavy/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/heavy/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/heavy/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/heavy/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hjson/bin/hjson"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hoek/lib/escape.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/ignore/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/in-publish/in-install.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/in-publish/in-publish.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/in-publish/not-in-install.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/in-publish/not-in-publish.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/lib/directory.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/lib/etag.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/lib/file.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/lib/fs.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/inert/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/install-artifact-from-github/bin/install-from-cache.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/iron/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/iron/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/iron/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/iron/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/isemail/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/items/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/items/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/items/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/items/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/joi/lib/errors.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/joi/lib/types/string/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/js-yaml/bin/js-yaml.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/jsesc/bin/jsesc"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/json5/lib/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/make-dir/node_modules/semver/bin/semver.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/micromatch/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/mimos/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/mimos/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/mkdirp/bin/cmd.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/mustache/bin/mustache"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/nan/tools/1to2.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/nigel/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/nigel/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/nigel/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/bin/node-gyp.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/gyp"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/gyp_main.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/MSVSSettings_test.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/__init__.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/common_test.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/easy_xml_test.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/flock_tool.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/generator/msvs_test.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/input_test.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/mac_tool.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/pylib/gyp/win_tool.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/setup.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/test_gyp.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/tools/graphviz.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/tools/pretty_gyp.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/tools/pretty_sln.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/gyp/tools/pretty_vcproj.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/node_modules/rimraf/bin.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-gyp/node_modules/semver/bin/semver.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/node-jose/node_modules/uuid/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/nopt/bin/nopt.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/opn/xdg-open"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/oppsy/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/oppsy/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/oppsy/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/pegjs/bin/pegjs"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/pez/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/pez/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/pez/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/lib/constants.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/lib/parse.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/lib/picomatch.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/lib/scan.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/lib/utils.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/picomatch/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/podium/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/podium/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/podium/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/podium/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/.github/actions/linux-alpine-node-10/entrypoint.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/.github/actions/linux-alpine-node-12/entrypoint.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/.github/actions/linux-alpine-node-14/entrypoint.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/.github/actions/linux-node-10/entrypoint.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/.github/actions/linux-node-12/entrypoint.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/vendor/re2/make_perl_groups.pl"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/vendor/re2/make_unicode_casefold.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/re2/vendor/re2/make_unicode_groups.py"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/react-dropzone/dist/es/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/react-dropzone/src/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/replace-ext/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/request/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/request/node_modules/uuid/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/rimraf/bin.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/secure-json-parse/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/secure-json-parse/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/secure-json-parse/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/semver/bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/lib/request.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/lib/response.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/shot/lib/symbols.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/spdx-license-ids/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/sshpk/bin/sshpk-conv"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/sshpk/bin/sshpk-sign"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/sshpk/bin/sshpk-verify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/statehood/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/statehood/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/statehood/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/statehood/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/subtext/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/tar/node_modules/mkdirp/bin/cmd.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/teamwork/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/teamwork/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/teamwork/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/teamwork/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/topo/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/topo/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/topo/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/topo/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/uuid/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vise/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vise/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vise/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vision/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vision/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/vision/lib/manager.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/which/bin/node-which"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wrap-ansi/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/lib/payload.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/lib/recorder.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/node_modules/wreck/lib/tap.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/history/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/hoek/lib/escape.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/performance-now/test/scripts/delayed-call.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/performance-now/test/scripts/delayed-require.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/performance-now/test/scripts/difference.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/performance-now/test/scripts/initial-value.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/prop-types/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/react-router-dom/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAlertingKibana/node_modules/react-router/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAnomalyDetectionKibana/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAnomalyDetectionKibana/node_modules/babel-polyfill/scripts/build-dist.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAnomalyDetectionKibana/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAnomalyDetectionKibana/node_modules/prop-types/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroAnomalyDetectionKibana/node_modules/react-redux/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroGanttChartKibana/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroGanttChartKibana/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroGanttChartKibana/node_modules/prop-types/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/atob"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/babel"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/babel-external-helpers"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/upgrade-blueprint-2.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/.bin/upgrade-blueprint-3.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@babel/cli/bin/babel-external-helpers.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@babel/cli/bin/babel.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/core/scripts/upgrade-blueprint-2.0.0-rename.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/core/scripts/upgrade-blueprint-3.0.0-rename.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-16.eot"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-16.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-16.woff"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-20.eot"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-20.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/icons/resources/icons/icons-20.woff"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/select/node_modules/.bin/upgrade-blueprint-2.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@blueprintjs/select/node_modules/.bin/upgrade-blueprint-3.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@nteract/presentational-components/node_modules/.bin/upgrade-blueprint-2.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/@nteract/presentational-components/node_modules/.bin/upgrade-blueprint-3.0.0-rename"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/anser/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/anser/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/anser/lib/index.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/anser/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/anser/package.json"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/arr-diff/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/arr-flatten/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/arr-flatten/README.md"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/array-unique/LICENSE"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/array-unique/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/atob/bin/atob.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/html-to-react/scripts/build-under-yourbase"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/make-dir/node_modules/.bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/micromatch/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/CHANGELOG.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/lib/constants.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/lib/parse.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/lib/picomatch.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/lib/scan.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/lib/utils.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/picomatch/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/prismjs/components/prism-n4js.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/prismjs/components/prism-n4js.min.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/prismjs/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/prop-types/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/react-dom/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/react-transition-group/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/react/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/replace-ext/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/scheduler/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/semver/bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/source-map-resolve/node_modules/.bin/atob"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/upath/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroNotebooksKibana/node_modules/warning/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/.chromium/headless_shell"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/.chromium/locales"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/acorn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/escodegen"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/esgenerate"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/esparse"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/esvalidate"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/extract-zip"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/mime"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/mkdirp"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/rimraf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/showdown"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/sshpk-conv"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/sshpk-sign"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/sshpk-verify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/.bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/acorn-globals/node_modules/.bin/acorn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/acorn/bin/acorn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/babel-polyfill/scripts/build-dist.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/doc-path/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/doc-path/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/lib/LICENSE-jsbn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/lib/ec.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/lib/sec.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/ecc-jsbn/test.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/enzyme-adapter-react-16/node_modules/.bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/enzyme-adapter-utils/node_modules/.bin/semver"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/escodegen/bin/escodegen.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/escodegen/bin/esgenerate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/escodegen/node_modules/.bin/esparse"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/escodegen/node_modules/.bin/esvalidate"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/esprima/bin/esparse.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/esprima/bin/esvalidate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/extract-zip/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/extract-zip/node_modules/.bin/mkdirp"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/extract-zip/node_modules/mkdirp/bin/cmd.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/history/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/html-to-react/scripts/build-under-yourbase"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/http-signature/node_modules/.bin/sshpk-conv"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/http-signature/node_modules/.bin/sshpk-sign"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/http-signature/node_modules/.bin/sshpk-verify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/jsdom/node_modules/.bin/acorn"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/jsdom/node_modules/.bin/escodegen"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/jsdom/node_modules/.bin/esgenerate"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/json-2-csv/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/json-2-csv/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/json-2-csv/src/json2csv.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/loose-envify/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/mime/cli.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/performance-now/test/scripts/delayed-call.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/performance-now/test/scripts/delayed-require.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/performance-now/test/scripts/difference.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/performance-now/test/scripts/initial-value.coffee"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/pn/scripts/generate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/prop-types-exact/install-relevant-react.sh"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/prop-types/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/puppeteer-core/node_modules/.bin/extract-zip"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/puppeteer-core/node_modules/.bin/mime"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/puppeteer-core/node_modules/.bin/rimraf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/react-router-dom/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/react-router/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/react-transition-group/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/replace-ext/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/request/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/request/node_modules/.bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/rimraf/bin.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/scheduler/node_modules/.bin/loose-envify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/semver/bin/semver"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/set-interval-async/examples/dynamic"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/set-interval-async/examples/fixed"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/set-interval-async/test/resources/dynamic"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/set-interval-async/test/resources/fixed"
%dir %attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/set-interval-async/test/resources/legacy"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/showdown/bin/showdown.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/sshpk/bin/sshpk-conv"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/sshpk/bin/sshpk-sign"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/sshpk/bin/sshpk-verify"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/LICENSE"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.min.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.min.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/es5/uri.all.min.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/index.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/index.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-iri.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-iri.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-iri.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-uri.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-uri.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/regexps-uri.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/http.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/http.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/http.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/https.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/https.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/https.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/mailto.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/mailto.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/mailto.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn-uuid.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn-uuid.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn-uuid.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/urn.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/ws.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/ws.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/ws.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/wss.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/wss.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/schemes/wss.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/uri.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/uri.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/uri.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/util.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/util.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/dist/esnext/util.js.map"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uri-js/yarn.lock"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/uuid/bin/uuid"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroReportsKibana/node_modules/wrap-ansi/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/lib/index.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/applyToDefaults.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/assert.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/bench.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/block.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/clone.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/contain.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/deepEqual.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/error.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/escapeHeaderAttribute.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/escapeHtml.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/escapeJson.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/escapeRegex.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/flatten.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/ignore.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/index.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/intersect.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/isPromise.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/merge.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/once.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/reach.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/reachTemplate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/stringify.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/types.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/utils.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/lib/wait.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/boom/node_modules/@hapi/hoek/package.json"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/bourne/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/bourne/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/bourne/lib/index.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/cryptiles/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/cryptiles/README.md"
%attr(0754, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/cryptiles/lib/index.d.ts"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/cryptiles/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/cryptiles/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/applyToDefaults.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/assert.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/bench.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/block.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/clone.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/contain.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/deepEqual.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/error.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/escapeHeaderAttribute.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/escapeHtml.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/escapeJson.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/escapeRegex.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/flatten.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/ignore.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/index.d.ts"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/intersect.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/isPromise.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/merge.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/once.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/reach.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/reachTemplate.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/stringify.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/types.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/utils.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/lib/wait.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/hoek/package.json"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/lib/payload.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/lib/recorder.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/lib/tap.js"
%attr(0744, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/node_modules/@hapi/boom/LICENSE.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/node_modules/@hapi/boom/README.md"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/plugins/opendistroSecurityKibana/node_modules/@hapi/wreck/node_modules/@hapi/boom/lib/index.js"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/LICENSE.txt"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Bold.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-BoldItalic.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Italic.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Light.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-LightItalic.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Medium.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-MediumItalic.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Regular.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-Thin.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/core/server/core_app/assets/fonts/roboto_mono/RobotoMono-ThinItalic.ttf"
%attr(0755, wazuh-wui, wazuh-wui) "%{_localstatedir}/usr/share/wazuh-wui/src/plugins/home/public/assets/logos/osquery.svg"


%changelog
* Wed Apr 28 2021 support <info@wazuh.com> - 4.3.0
- More info: https://documentation.wazuh.com/current/release-notes/