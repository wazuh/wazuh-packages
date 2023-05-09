FROM debian:8

ENV DEBIAN_FRONTEND noninteractive

RUN echo 'Acquire::Check-Valid-Until "false";' >> /etc/apt/apt.conf && \
    echo "deb http://archive.debian.org/debian jessie contrib main non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --force-yes apt-utils && \
    apt-get install -y --force-yes \
    curl sudo wget expect gnupg build-essential \
    devscripts equivs selinux-basics procps gawk

# Add the script to build the Debian package
ADD builder.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]
