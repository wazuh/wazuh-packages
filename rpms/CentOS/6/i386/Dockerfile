FROM i386/centos:6

# Install all the necessary tools to build the packages
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
RUN sed -i 's/$basearch/i386/g' /etc/yum.repos.d/CentOS-Base.repo
RUN yum -y install util-linux-ng centos-release-scl \
    gcc-multilib make git openssh-clients rpm-build \
    sudo gnupg automake autoconf libtool \
    policycoreutils-python yum-utils epel-release \
    redhat-rpm-config rpm-devel

RUN yum-builddep python34 -y

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Create the build directory
RUN mkdir /build_wazuh
ADD wazuh.spec /build_wazuh/wazuh.spec

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
