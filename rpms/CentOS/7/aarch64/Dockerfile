FROM arm64v8/centos:7

# Enable EPEL
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Install all the necessary tools to build the packages
RUN yum install -y gcc make git \
    openssh-clients sudo gnupg file-devel\
    automake autoconf libtool policycoreutils-python \
    yum-utils system-rpm-config rpm-devel \
    gettext nspr nspr-devel \
    nss nss-devel libdb libdb-devel \
    zlib zlib-devel rpm-build bison \
    sharutils bzip2-devel xz-devel lzo-devel \
    e2fsprogs-devel libacl-devel libattr-devel \
    openssl-devel libxml2-devel kexec-tools elfutils \
    libarchive-devel elfutils-libelf-devel \
    elfutils-libelf patchelf elfutils-devel libgcrypt-devel \
    libarchive-devel libarchive nodejs

# Update rpmbuild, rpm and autoconf
RUN curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && ./configure && make && make install

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