FROM i386/debian:7

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://archive.debian.org/debian/ wheezy contrib main non-free" > /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian/ wheezy contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y apt-utils && \
    apt-get install -y --force-yes \
    curl gcc-multilib make sudo expect gnupg fakeroot perl-base=5.14.2-21+deb7u3 \
    perl libc-bin=2.13-38+deb7u10 libc6=2.13-38+deb7u10 libc6-dev \
    build-essential cdbs devscripts equivs automake autoconf libtool \
    libaudit-dev selinux-basics util-linux libdb5.1=5.1.29-5 libdb5.1-dev \
    libssl1.0.0=1.0.1e-2+deb7u20

# Add Debian's source repository
RUN apt-get update && apt-get build-dep python3.2 -y

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package

RUN chmod +x /usr/local/bin/build_package && \
    useradd -ms /bin/bash wazuh-builder

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh
VOLUME /etc/wazuh/checksum

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
