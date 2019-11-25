FROM centos:7

RUN yum install -y curl

# Create the build directory and add file
ADD build.sh /
RUN mkdir /wazuh_splunk_app && \
    chmod +x /build.sh

# Add the volumes
RUN mkdir -p /wazuh_splunk_app

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]