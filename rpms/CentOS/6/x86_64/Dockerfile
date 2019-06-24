FROM centos:6
# Install all the necessary tools to build the packages
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
RUN yum -y install centos-release-scl gcc make git \
    openssh-clients rpm-build sudo gnupg \
    automake autoconf libtool policycoreutils-python \
    yum-utils epel-release redhat-rpm-config rpm-devel

# Warning: this repo has been disabled by the vendor
RUN mv /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo.old
RUN yum-builddep python34 -y

RUN curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
RUN yum install -y nodejs

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Create the build directory
RUN mkdir /build_wazuh
ADD wazuh.spec /build_wazuh/wazuh.spec

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh
VOLUME /etc/wazuh/checksum

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
