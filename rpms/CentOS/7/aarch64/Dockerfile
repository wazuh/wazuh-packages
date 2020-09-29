FROM arm64v8/centos:7

# Enable EPEL
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Install all the necessary tools to build the packages
RUN yum install -y gcc make wget git \
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
    libarchive-devel libarchive bluez-libs-devel bzip2 \
    desktop-file-utils expat-devel findutils gcc-c++ gdbm-devel \
    glibc-devel gmp-devel gnupg2 libappstream-glib \
    libffi-devel libtirpc-devel libGL-devel libuuid-devel \
    libX11-devel ncurses-devel pkgconfig readline-devel \
    redhat-rpm-config sqlite-devel gdb tar tcl-devel tix-devel tk-devel \
    valgrind-devel python-rpm-macros python34 nodejs

RUN curl -O https://www.openssl.org/source/openssl-1.1.1g.tar.gz && \
    tar -xzf openssl-1.1.1g.tar.gz && cd openssl* && \
    ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)' && \
    make -j $(nproc) && make install && make install

RUN curl -O https://packages.wazuh.com/utils/nodejs/node-v12.16.1-linux-arm64.tar.xz && \
    tar -xJf node-v12.16.1-linux-arm64.tar.xz && cd node-v12.16* && cp -R * /usr/local/

# Update rpmbuild, rpm and autoconf
RUN curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && ./configure && make -j $(nproc) && make install

RUN curl -O https://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    ./configure --without-lua && make -j $(nproc) && make install

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb

RUN curl -OL https://ftp.gnu.org/gnu/gcc/gcc-5.5.0/gcc-5.5.0.tar.gz && \
    tar xzf gcc-5.5.0.tar.gz  && \
    ln -sf gcc-5.5.0 gcc && \
    cd gcc-5.5.0/ && \
    ./contrib/download_prerequisites && \
    cd .. && mkdir gcc-build && cd gcc-build && \
    ../gcc-5.5.0/configure --prefix=/usr/local/gcc-5.5.0 --enable-languages=c,c++ --disable-multilib --disable-libsanitizer --disable-bootstrap && \
    make && make install && \
    echo "export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0/" >> /root/.bashrc && \
    echo "export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib64/" >> /root/.bashrc && \
    echo "export PATH=/usr/local/gcc-5.5.0/bin:$PATH" >> /root/.bashrc && \
    rm -rf /usr/bin/cc && rm /usr/bin/c++

RUN curl -OL https://github.com/Kitware/CMake/releases/download/v3.18.3/cmake-3.18.3.tar.gz && \
    tar -zxvf cmake-3.18.3.tar.gz && \
    cd cmake-3.18.3 && \
    export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0/ && \
    export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib64/ && \
    ./bootstrap CC=/usr/local/gcc-5.5.0/bin/gcc CXX=/usr/local/gcc-5.5.0/bin/g++ && \
    gmake && gmake install && \
    ln -s /usr/local/gcc-5.5.0/bin/gcc /usr/bin/cc && \
    ln -s /usr/local/gcc-5.5.0/bin/g++ /usr/bin/c++

RUN rm -rf autoconf-* rpm-* libarchive-* gcc-* cmake-* openssl-* node-v* /root/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]