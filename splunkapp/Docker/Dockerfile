FROM centos:7

# Create the build directory and add file
ADD     build.sh /
RUN     mkdir /wazuh_splunk_app && \
        chmod +x /build.sh && \
        mkdir /pkg


# Add the volumes
VOLUME  /wazuh_splunk_app

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]
