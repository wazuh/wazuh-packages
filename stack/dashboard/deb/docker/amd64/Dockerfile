FROM rockylinux:8.5 as builder_base

ARG FUTURE
ARG REVISION
ARG REFERENCE

# Install all the necessary tools to build the packages
RUN yum clean all && yum update -y
RUN yum install -y \
    curl \
    tar \
    findutils \
    git \
    xz  \
    gcc \
    make \
    bc \
    sed \
    gzip \
    autoconf \
    automake \
    libtool \
    jq

RUN git clone https://github.com/google/brotli.git

RUN cd brotli && ./bootstrap && ./configure --prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --libexecdir=/usr/lib64/brotli --libdir=/usr/lib64/brotli --datarootdir=/usr/share --mandir=/usr/share/man/man1 --docdir=/usr/share/doc \
    && make && make install

# Add the script
ADD builder_base.sh /usr/local/bin/builder_base
RUN chmod +x /usr/local/bin/builder_base

ADD files/ /root/stack/dashboard/base/files/
ADD VERSION /root/VERSION

RUN if [ $REFERENCE ];then \
    /usr/local/bin/builder_base $FUTURE $REVISION $REFERENCE; \
    else \
    /usr/local/bin/builder_base $FUTURE $REVISION; \
    fi

FROM debian:10

ARG VERSION
ARG REVISION
ENV DEBIAN_FRONTEND noninteractive

COPY --from=builder_base "/tmp/output/wazuh-dashboard-base-$VERSION-$REVISION-linux-x64.tar.xz" "/opt/wazuh-dashboard-base-$VERSION-$REVISION-linux-x64.tar.xz"

# Installing necessary packages
RUN apt-get update && apt-get install -y apt-utils && \
    apt-get install -y \
    curl \
    sudo \
    wget \
    expect \
    gnupg \
    build-essential \
    devscripts \
    equivs \
    selinux-basics \
    procps \
    gawk

# Add the script to build the Debian package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]