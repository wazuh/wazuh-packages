FROM scratch

# Add the tar.gz with all the files needed
ADD centos-5-i386.tar.gz /

# Install Perl 5.10
RUN wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz && gunzip perl-5.10.1.tar.gz && \
    tar -xf perl*.tar && cd /perl-5.10.1 && ./Configure -des -Dcc='gcc' && \
    make && make install && ln -fs /usr/local/bin/perl /bin/perl && cd / && rm -rf /perl-5.10.1*

RUN curl -OL http://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/utils/tests/openssl-1.1.1a.tar.gz && \
    tar xf openssl-1.1.1a.tar.gz && cd openssl-1.1.1a && \
    linux32 ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    linux32 make && linux32 make install && echo "/usr/local/ssl/lib" > /etc/ld.so.conf.d/openssl-1.1.1a.conf && \
    ldconfig -v && cd / && rm -rf openssl-1.1.1a*

RUN curl -OL https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/utils/tests/curl-7.63.0.tar.gz && \
    tar xf curl-7.63.0.tar.gz && cd curl-7.63.0 && linux32 ./configure --with-ssl=/usr/local/ssl && \
    linux32 make && linux32 make install && cd / && rm -rf curl*


# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Create the build directory
RUN mkdir /build_wazuh

# Add the volumes
RUN mkdir -p /var/local/wazuh
RUN mkdir -p /etc/wazuh/checksum

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
