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
    https://packages.wazuh.com/utils/nodejs/nodejs-8.9.4-2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/nodejs-devel-8.9.4-2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/npm-5.6.0-1.8.9.4.2.el7.ppc64le.rpm \
    https://packages.wazuh.com/utils/nodejs/nodejs-debuginfo-8.9.4-2.el7.ppc64le.rpm


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

RUN rm -rf gcc-* cmake-*

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]