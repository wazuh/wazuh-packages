FROM i386/debian:7

# Installing necessary packages
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y apt-utils
RUN apt-get install -y curl gcc-multilib make sudo expect \
    gnupg fakeroot build-essential cdbs devscripts equivs \
    automake autoconf libtool libaudit-dev selinux-basics \
    util-linux

# Add Debian's source repository
RUN echo "deb-src http://deb.debian.org/debian wheezy main" >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get build-dep python3.2 -y

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh

RUN useradd -ms /bin/bash wazuh-builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]