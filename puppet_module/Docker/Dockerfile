FROM ubuntu:22.04

RUN apt update && apt install -y curl jq

RUN curl -O https://apt.puppet.com/puppet-tools-release-focal.deb && \
    dpkg -i puppet-tools-release-focal.deb && \
    apt-get update && \
    apt-get install pdk

RUN pdk set config user.analytics.disabled false --type boolean --force

# Create the build directory and add file
ADD build.sh /
RUN chmod +x /build.sh

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]
