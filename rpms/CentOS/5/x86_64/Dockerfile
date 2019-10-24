FROM centos:5.11

RUN rm /etc/yum.repos.d/* && echo "exactarch=1" >> /etc/yum.conf
COPY CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
RUN yum clean all && yum update -y && yum downgrade -y libselinux

# Install sudo, SSH and compilers
RUN yum install -y sudo ca-certificates make gcc curl initscripts tar \
    rpm-build automake autoconf libtool wget libselinux devicemapper \
    libselinux-python krb5-libs policycoreutils checkpolicy

RUN yum groupinstall -y "Development tools"
RUN yum install -y zlib-devel bzip2-devel openssl-devel ncurses-devel

# Install Perl 5.10, OpenSSL 1.1.1 and curl
RUN wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz && gunzip perl-5.10.1.tar.gz && \
    tar -xf perl*.tar && cd /perl-5.10.1 && ./Configure -des -Dcc='gcc' && \
    make && make install && ln -fs /usr/local/bin/perl /bin/perl && cd / && rm -rf /perl-5.10.1*

RUN curl -OL http://packages-dev.wazuh.com/utils/pkg/openssl-1.1.1a.tar.gz && \
    tar xf openssl-1.1.1a.tar.gz && cd openssl-1.1.1a && \
    CFLAGS="-fPIC" ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    make && make install && echo "/usr/local/ssl/lib" > /etc/ld.so.conf.d/openssl-1.1.1a.conf && \
    ldconfig -v && cd / && rm -rf openssl-1.1.1a*

RUN curl -OL http://packages-dev.wazuh.com/utils/pkg/curl-7.63.0.tar.gz && \
    tar xf curl-7.63.0.tar.gz && cd curl-7.63.0 && ./configure --with-ssl=/usr/local/ssl && \
    make && make install && cd / && rm -rf curl*

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
