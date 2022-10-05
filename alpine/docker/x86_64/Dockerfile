FROM amd64/alpine:3.16.0

# Install all the necessary tools to build the packages
RUN apk add ca-certificates curl alpine-sdk sudo less openssh \
    openssl openssl-dev libgcc bash make gcc g++ cmake curl automake \
    linux-headers autoconf libtool python3 aws-cli jq && \
    ln -s /usr/include/linux/a.out.h /usr/include/a.out.h && \
    addgroup -S wazuh && adduser -S wazuh -G wazuh && \
    mkdir /output && mkdir /wazuh

# Add the scripts to build the Alpine package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]