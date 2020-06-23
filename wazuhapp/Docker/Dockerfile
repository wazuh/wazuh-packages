FROM centos:7

# Create the build directory and add file
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    curl -sL https://rpm.nodesource.com/setup_8.x | bash - && \
    yum install git nodejs -y && \
    npm install -g n && \
    npm install -g yarn@1.10.1

ADD build.sh /
RUN chmod +x /build.sh

# Add the volumes
RUN mkdir /wazuh_app /source

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]