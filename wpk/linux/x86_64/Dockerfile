FROM centos:6
ENV PATH=/opt/rh/python27/root/usr/bin:$PATH

RUN yum -y install centos-release-scl epel-release && \
    yum -y install gcc make git python34 python34-pip python34-devel python34-cffi \
    jq centos-release-scl sudo gnupg automake \
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

RUN mv /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo.old
RUN yum-builddep python34 -y
RUN pip3 install cryptography==2.9.2 awscli

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-5.5.0.tar.gz && \
    tar xzf gcc-5.5.0.tar.gz  && cd gcc-5.5.0/ && \
    ./contrib/download_prerequisites && \
    ./configure --prefix=/usr/local/gcc-5.5.0 --enable-languages=c,c++ \
        --disable-multilib --disable-libsanitizer --disable-bootstrap && \
    make -j$(nproc) && make install && \
    ln -fs /usr/local/gcc-5.5.0/bin/g++ /usr/bin/c++ && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-5.5.0/include/c++/5.5.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-5.5.0/lib64/"
ENV PATH "/usr/local/gcc-5.5.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    ./bootstrap --no-system-curl CC=/usr/local/gcc-5.5.0/bin/gcc \
        CXX=/usr/local/gcc-5.5.0/bin/g++ && \
    make -j$(nproc) && make install && cd / && rm -rf cmake-*

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
