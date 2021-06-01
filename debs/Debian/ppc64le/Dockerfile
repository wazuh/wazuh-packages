FROM ppc64le/debian:stretch

ENV DEBIAN_FRONTEND noninteractive
ENV PATH /usr/local/lib/nodejs/node-v10.16.0-linux-ppc64le/bin:$PATH

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package

# Installing necessary packages
RUN echo "deb http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y apt-utils && \
    apt-get install -y --force-yes \
    curl gcc make sudo expect gnupg perl-base perl wget \
    libc-bin libc6 libc6-dev build-essential \
    cdbs devscripts equivs automake autoconf libtool libaudit-dev selinux-basics \
    libdb5.3 libdb5.3 libssl1.0.2 gawk libsigsegv2

# Add Debian's source repository
RUN apt-get update &&  apt-get build-dep python3.5 -y &&\
    chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
