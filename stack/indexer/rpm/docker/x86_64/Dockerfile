FROM rockylinux:8.5

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
    rpm-build \
    findutils \
    git \
    java-11-openjdk-devel

# Add the scripts to build the RPM package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Add the script to build the Indexer base
ADD builder_base.sh /usr/local/bin/builder_base
RUN chmod +x /usr/local/bin/builder_base

# Set the entrypoint
CMD ["/usr/local/bin/builder"]