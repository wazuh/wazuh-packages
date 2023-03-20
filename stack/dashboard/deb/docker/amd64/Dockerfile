FROM debian:10

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN apt-get update && apt-get install -y --allow-change-held-packages apt-utils && \
    apt-get install -y --allow-change-held-packages \
    curl sudo wget expect gnupg build-essential \
    devscripts equivs selinux-basics procps gawk

# Add the script to build the Debian package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]