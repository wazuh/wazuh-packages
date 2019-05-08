FROM centos:7

# Create the build directory and add file
ADD build.sh /
RUN mkdir /wazuh_app && \
    mkdir /source && \
    chmod +x /build.sh && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    curl -sL https://rpm.nodesource.com/setup_8.x | bash - && \
    yum install nodejs -y && \
    npm install -g n && \
    npm install -g yarn@1.10.1 


# Add the volumes
VOLUME /wazuh_app
VOLUME /source

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]

