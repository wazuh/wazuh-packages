Summary:     Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring
Name:        wazuh-jdk
Version:     4.2.0
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
URL:         https://www.wazuh.com/
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Wazuh, Inc <info@wazuh.com>
Packager:    Wazuh, Inc <info@wazuh.com>
AutoReqProv: no

Requires: coreutils
BuildRequires: tar

ExclusiveOS: linux

# -----------------------------------------------------------------------------

%description
Wazuh helps you to gain security visibility into your infrastructure by monitoring
hosts at an operating system and application level. It provides the following capabilities:
log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring

# -----------------------------------------------------------------------------

%prep
curl -OL https://packages-dev.wazuh.com/deps/openjdk-11.0.2_linux-x64_bin.tar.gz
tar -zvxf openjdk-11.0.2_linux-x64_bin.tar.gz

# -----------------------------------------------------------------------------

%install
# Clean BUILDROOT
rm -fr %{buildroot}

# Create directories
mkdir -p %{buildroot}%{_initrddir}
mkdir -p %{buildroot}%{_localstatedir}

# Copy the installed files into buildroot directory
cp -pr jdk-11.0.2/* %{buildroot}%{_localstatedir}/

exit 0

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%%defattr(0644,root,root)
%dir %attr(750, root, root) %{_localstatedir}/bin
%attr(755, root, root) %{_localstatedir}/bin/jaotc
%attr(755, root, root) %{_localstatedir}/bin/jar
%attr(755, root, root) %{_localstatedir}/bin/jarsigner
%attr(755, root, root) %{_localstatedir}/bin/java
%attr(755, root, root) %{_localstatedir}/bin/javac
%attr(755, root, root) %{_localstatedir}/bin/javadoc
%attr(755, root, root) %{_localstatedir}/bin/javap
%attr(755, root, root) %{_localstatedir}/bin/jcmd
%attr(755, root, root) %{_localstatedir}/bin/jconsole
%attr(755, root, root) %{_localstatedir}/bin/jdb
%attr(755, root, root) %{_localstatedir}/bin/jdeprscan
%attr(755, root, root) %{_localstatedir}/bin/jdeps
%attr(755, root, root) %{_localstatedir}/bin/jhsdb
%attr(755, root, root) %{_localstatedir}/bin/jimage
%attr(755, root, root) %{_localstatedir}/bin/jinfo
%attr(755, root, root) %{_localstatedir}/bin/jjs
%attr(755, root, root) %{_localstatedir}/bin/jlink
%attr(755, root, root) %{_localstatedir}/bin/jmap
%attr(755, root, root) %{_localstatedir}/bin/jmod
%attr(755, root, root) %{_localstatedir}/bin/jps
%attr(755, root, root) %{_localstatedir}/bin/jrunscript
%attr(755, root, root) %{_localstatedir}/bin/jshell
%attr(755, root, root) %{_localstatedir}/bin/jstack
%attr(755, root, root) %{_localstatedir}/bin/jstat
%attr(755, root, root) %{_localstatedir}/bin/jstatd
%attr(755, root, root) %{_localstatedir}/bin/keytool
%attr(755, root, root) %{_localstatedir}/bin/pack200
%attr(755, root, root) %{_localstatedir}/bin/rmic
%attr(755, root, root) %{_localstatedir}/bin/rmid
%attr(755, root, root) %{_localstatedir}/bin/rmiregistry
%attr(755, root, root) %{_localstatedir}/bin/serialver
%attr(755, root, root) %{_localstatedir}/bin/unpack200

%dir %attr(750, root, root) %{_localstatedir}/conf
%attr(644, root, root) %{_localstatedir}/conf/*

%dir %attr(750, root, root) %{_localstatedir}/include
%attr(644, root, root) %{_localstatedir}/include/*

%dir %attr(750, root, root) %{_localstatedir}/jmods
%attr(644, root, root) %{_localstatedir}/jmods/*

%dir %attr(750, root, root) %{_localstatedir}/legal
%attr(644, root, root) %{_localstatedir}/legal/*

%dir %attr(750, root, root) %{_localstatedir}/lib
%attr(644, root, root) %{_localstatedir}/lib/*

%attr(644, root, root) %{_localstatedir}/release

# -----------------------------------------------------------------------------

%changelog
* Mon Apr 26 2021 support <info@wazuh.com> - 4.2.0
- More info: https://documentation.wazuh.com/current/release-notes/
