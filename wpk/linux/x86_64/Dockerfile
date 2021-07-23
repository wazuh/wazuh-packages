FROM centos:6

RUN rm /etc/yum.repos.d/* && echo "exactarch=1" >> /etc/yum.conf
COPY CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo

RUN yum -y install epel-release && \
    yum -y install gcc make git python34 python34-pip python34-devel python34-cffi \
    jq sudo gnupg automake \
    autoconf wget libtool policycoreutils-python \
    yum-utils epel-release redhat-rpm-config rpm-devel \
    autopoint gettext nspr nspr-devel \
    nss nss-devel kenel-headers magic magic-devel \
    db4 db4-devel zlib zlib-devel rpm-build bison \
    sharutils bzip2-devel xz-devel lzo-devel \
    e2fsprogs-devel libacl-devel libattr-devel \
    openssl-devel libxml2-devel kexec-tools elfutils \
    libarchive-devel elfutils-libelf-devel \
    elfutils-libelf patchelf elfutils-devel libgcrypt-devel

RUN yum-builddep python34 -y

RUN pip3 install cryptography==2.9.2 typing awscli

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ADD upgrade.sh /usr/local/bin/upgrade.sh
ADD pkg_installer.sh /usr/local/bin/pkg_installer.sh

ENTRYPOINT ["/usr/local/bin/run"]
