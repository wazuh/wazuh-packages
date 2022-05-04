FROM s390x/fedora

# Install all the necessary tools to build the packages
RUN yum clean all && yum update -y
RUN yum install -y cmake gcc make git wget curl

RUN yum install nodejs python3 rpm-build -y

RUN ln -sf /usr/bin/rpmbuild /usr/local/bin/rpmbuild

RUN yum install autoconf automake libtool perl -y

RUN yum install policycoreutils-python-utils -y

RUN yum install libcxx-devel -y
#RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
#    tar xzf gcc-9.4.0.tar.gz  && cd gcc-9.4.0/ && \
#    ./contrib/download_prerequisites && \
#    ./configure --prefix=/usr/local/gcc-9.4.0 --enable-languages=c,c++ \
#        --disable-multilib --disable-libsanitizer && \
#    make -j$(nproc) && make install && \
#    ln -fs /usr/local/gcc-9.4.0/bin/g++ /usr/bin/c++ && cd / && rm -rf gcc-*

#ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-9.4.0/include/c++/9.4.0/"
#ENV LD_LIBRARY_PATH "/usr/local/gcc-9.4.0/lib64/"
#ENV PATH "/usr/local/gcc-9.4.0/bin:${PATH}"

#RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
#    tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
#    ./bootstrap --no-system-curl CC=/usr/local/gcc-9.4.0/bin/gcc \
#        CXX=/usr/local/gcc-9.4.0/bin/g++ && \
#    make -j$(nproc) && make install && cd / && rm -rf cmake-*

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
