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

FROM rockylinux:8.5

ARG VERSION
ARG REVISION

COPY --from=builder_base "/tmp/output/wazuh-indexer-base-$VERSION-$REVISION-linux-x64.tar.xz" "/opt/wazuh-indexer-base-$VERSION-$REVISION-linux-x64.tar.xz"

# Install all the necessary tools to build the packages
RUN yum clean all && yum update -y
RUN yum install -y openssh-clients \
    sudo \
    gnupg \
    yum-utils \
    epel-release \
    redhat-rpm-config \
    rpm-devel \
    zlib \
    zlib-devel \
    rpm-build

# Add the scripts to build the RPM package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]