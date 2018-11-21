FROM scratch

# Add the tar.gz with all the files needed
ADD centos-5-i386.tar.gz /

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Create the build directory
RUN mkdir /build_wazuh
ADD wazuh.spec /build_wazuh/wazuh.spec

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
