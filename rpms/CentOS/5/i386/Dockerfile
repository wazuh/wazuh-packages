FROM scratch

# Add the tar.gz with all the files needed
ADD centos-5-i386.tar.gz /

# Install Perl 5.10
RUN wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz && gunzip perl-5.10.1.tar.gz && \
    tar -xf perl*.tar && cd /perl-5.10.1 && ./Configure -des -Dcc='gcc' && \
    make && make install && ln -fs /usr/local/bin/perl /bin/perl && cd / && rm -rf /perl-5.10.1*

RUN curl -OL http://packages-dev.wazuh.com/utils/pkg/openssl-1.1.1a.tar.gz && \
    tar xf openssl-1.1.1a.tar.gz && cd openssl-1.1.1a && \
    linux32 ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    linux32 make && linux32 make install && echo "/usr/local/ssl/lib" > /etc/ld.so.conf.d/openssl-1.1.1a.conf && \
    ldconfig -v && cd / && rm -rf openssl-1.1.1a*

RUN curl -OL http://packages-dev.wazuh.com/utils/pkg/curl-7.63.0.tar.gz && \
    tar xf curl-7.63.0.tar.gz && cd curl-7.63.0 && linux32 ./configure --with-ssl=/usr/local/ssl && \
    linux32 make && linux32 make install && cd / && rm -rf curl*

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
