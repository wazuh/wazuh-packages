FROM i386/centos:6

# Install all the necessary tools to build the packages
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
RUN sed -i 's/$basearch/i386/g' /etc/yum.repos.d/CentOS-Base.repo
RUN yum -y install util-linux-ng centos-release-scl \
    gcc-multilib make git openssh-clients \
    sudo gnupg automake autoconf libtool \
    policycoreutils-python yum-utils epel-release \
    redhat-rpm-config rpm-devel autopoint gettext \
    zlib zlib-devel nspr nspr-devel \
    nss nss-devel kenel-headers magic magic-devel \
    db4 db4-devel rpm-build bison \
    sharutils bzip2-devel xz-devel lzo-devel \
    e2fsprogs-devel libacl-devel libattr-devel \
    openssl-devel libxml2-devel kexec-tools elfutils \
    libarchive-devel elfutils-libelf-devel \
    elfutils-libelf patchelf elfutils-devel libgcrypt-devel 

RUN yum-builddep python34 -y

# Update rpmbuild, rpm and autoconf
RUN curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && linux32 ./configure && linux32 make && linux32 make install

RUN curl -O http://vault.centos.org/7.7.1908/os/Source/SPackages/libarchive-3.1.2-12.el7.src.rpm && \
    linux32 rpmbuild --rebuild libarchive-3.1.2-12.el7.src.rpm --target i386 && \
    rpm -Uvh /root/rpmbuild/RPMS/i386/*

RUN curl -O https://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    ./configure --without-lua && make && make install

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb

RUN rm -rf autoconf-* rpm-* libarchive-* /root/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
