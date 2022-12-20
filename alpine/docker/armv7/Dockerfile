FROM arm32v7/alpine:3.12.12

# Install all the necessary tools to build the packages
RUN linux32 apk add ca-certificates curl alpine-sdk sudo less openssh \
    openssl openssl-dev libgcc bash make gcc g++ cmake automake \
    linux-headers autoconf libtool python3 aws-cli jq gettext-dev procps && \
    mkdir /var/local/wazuh && mkdir /wazuh

# Add the scripts to build the Alpine package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]
