FROM rockylinux:8.5 as builder_base

ARG FUTURE
ARG REVISION
ARG REFERENCE

# Install all the necessary tools
RUN yum clean all && yum update -y
RUN yum install -y \
    findutils \
    git \
    java-11-openjdk-devel

# Add the script
ADD builder_base.sh /usr/local/bin/builder_base
RUN chmod +x /usr/local/bin/builder_base

ADD files/ /root/stack/indexer/base/files/
ADD VERSION /root/VERSION

RUN if [ $REFERENCE ];then \
    /usr/local/bin/builder_base $FUTURE $REVISION $REFERENCE; \
    else \
    /usr/local/bin/builder_base $FUTURE $REVISION; \
    fi

FROM debian:8

ARG VERSION
ARG REVISION

ENV DEBIAN_FRONTEND noninteractive

COPY --from=builder_base "/tmp/output/wazuh-indexer-base-$VERSION-$REVISION-linux-x64.tar.xz" "/opt/wazuh-indexer-base-$VERSION-$REVISION-linux-x64.tar.xz"

# Installing necessary packages
RUN apt-get update && apt-get install -y apt-utils \
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
