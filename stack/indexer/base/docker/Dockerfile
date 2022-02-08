FROM rockylinux:8.5

# Install all the necessary tools
RUN yum clean all && yum update -y
RUN yum install -y
    findutils \
    git \
    java-11-openjdk-devel

# Add the script
ADD generate_base.sh /usr/local/bin/generate_base
RUN chmod +x /usr/local/bin/generate_base

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/generate_base"]