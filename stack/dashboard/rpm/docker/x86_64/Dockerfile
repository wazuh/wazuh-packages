FROM centos:7

# Install all the necessary tools to build the packages
RUN yum clean all && yum update -y
RUN yum install -y openssh-clients sudo gnupg \
    yum-utils epel-release redhat-rpm-config rpm-devel \
    zlib zlib-devel rpm-build autoconf automake \
    glibc-devel libtool perl gcc make bc sed git \
    gzip

RUN git clone https://github.com/google/brotli.git

RUN cd brotli && ./bootstrap && ./configure --prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --libexecdir=/usr/lib64/brotli --libdir=/usr/lib64/brotli --datarootdir=/usr/share --mandir=/usr/share/man/man1 --docdir=/usr/share/doc \
    && make && make install

    

# Add the scripts to build the RPM package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]