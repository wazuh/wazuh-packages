Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-server
Version:     4.1.2
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
Requires:    wazuh-manager-4.1.2 filebeat-oss-7.9.1
AutoReqProv: no


ExclusiveOS: linux

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring


%install

mkdir -p %{_localstatedir}/config/
curl -so %{_localstatedir}/config/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/filebeat/7.x/filebeat.yml
curl -so %{_localstatedir}/config/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json
curl -so %{_localstatedir}/config/wazuh-filebeat-0.1.tar.gz https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz

chmod 640 %{_localstatedir}/config/filebeat.yml
chmod 640 %{_localstatedir}/config/wazuh-template.json
chmod 640 %{_localstatedir}/config/wazuh-template.json

%post
cp %{_localstatedir}/config/filebeat.yml /etc/filebeat/filebeat.yml
cp %{_localstatedir}/config/wazuh-template.json /etc/filebeat/wazuh-template.json
tar -xvz %{_localstatedir}/config/wazuh-filebeat-0.1.tar.gz -C /usr/share/filebeat/module


