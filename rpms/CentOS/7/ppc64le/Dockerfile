FROM ppc64le/centos:7
# Install all the necessary tools to build the packages

RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
RUN yum -y install centos-release-scl 
RUN mv /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo.old
RUN mv /etc/yum.repos.d/CentOS-SCLo-scl.repo /etc/yum.repos.d/CentOS-SCLo-scl.repo.old


RUN yum -y install gcc make git \
    openssh-clients rpm-build sudo gnupg \
    automake autoconf libtool policycoreutils-python \
    yum-utils epel-release redhat-rpm-config rpm-devel

# Warning: this repo has been disabled by the vendor
RUN mv /etc/yum.repos.d/CentOS-Sources.repo /etc/yum.repos.d/CentOS-Sources.repo.old
RUN yum-builddep python34 -y

RUN yum install -y \
    https://packages.wazuh.com/utils/nodejs/nodejs-8.9.4-2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/nodejs-devel-8.9.4-2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/npm-5.6.0-1.8.9.4.2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/nodejs-debuginfo-8.9.4-2.el7.ppc64le.rpm


# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]