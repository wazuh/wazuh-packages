FROM ppc64le/centos:7
# Install all the necessary tools to build the packages

RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
RUN yum -y install centos-release-scl
RUN mv /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo.old
RUN mv /etc/yum.repos.d/CentOS-SCLo-scl.repo /etc/yum.repos.d/CentOS-SCLo-scl.repo.old

RUN yum -y install gcc make wget git \
    openssh-clients rpm-build sudo gnupg \
    automake autoconf libtool policycoreutils-python \
    yum-utils epel-release redhat-rpm-config rpm-devel

# Warning: this repo has been disabled by the vendor
RUN mv /etc/yum.repos.d/CentOS-Sources.repo /etc/yum.repos.d/CentOS-Sources.repo.old
RUN yum-builddep python34 -y

RUN yum install -y \
    http://packages.wazuh.com/utils/nodejs/nodejs-8.9.4-2.el7.ppc64le.rpm \
    http://packages.wazuh.com/utils/nodejs/nodejs-devel-8.9.4-2.el7.ppc64le.rpm \
    http://packages.wazuh.com/utils/nodejs/npm-5.6.0-1.8.9.4.2.el7.ppc64le.rpm \
    http://packages.wazuh.com/utils/nodejs/nodejs-debuginfo-8.9.4-2.el7.ppc64le.rpm

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
    tar xzf gcc-9.4.0.tar.gz  && cd gcc-9.4.0/ && \
    ./contrib/download_prerequisites && \
    ./configure --prefix=/usr/local/gcc-9.4.0 --enable-languages=c,c++ \
        --disable-multilib --disable-libsanitizer && \
    make -j$(nproc) && make install && \
    ln -fs /usr/local/gcc-9.4.0/bin/g++ /usr/bin/c++ && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-9.4.0/include/c++/9.4.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-9.4.0/lib64/"
ENV PATH "/usr/local/gcc-9.4.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    ./bootstrap --no-system-curl CC=/usr/local/gcc-9.4.0/bin/gcc \
        CXX=/usr/local/gcc-9.4.0/bin/g++ && \
    make -j$(nproc) && make install && cd / && rm -rf cmake-* && \
    ln -sf /usr/bin/rpmbuild /usr/local/bin/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
