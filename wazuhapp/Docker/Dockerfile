FROM centos:8

# Install dependencies
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-centostesting && \
    curl -sL https://rpm.nodesource.com/setup_10.x | bash - && \
    yum install nodejs git gcc gcc-c++ make sudo zip python3 -y && \
    alternatives --set python /usr/bin/python3 && \
    npm install -g n 

ADD build.sh /
RUN chmod +x /build.sh

# Add the volumes
RUN mkdir /wazuh_app /source

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]
