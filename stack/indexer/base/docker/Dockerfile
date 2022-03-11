FROM rockylinux:8.5

# Install all the necessary tools
RUN yum clean all && yum update -y
RUN yum install -y \
    findutils \
    git \
    java-11-openjdk-devel

# Add the script
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]