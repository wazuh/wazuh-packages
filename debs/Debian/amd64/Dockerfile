FROM debian:7

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://archive.debian.org/debian/ wheezy contrib main non-free" > /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian/ wheezy contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y apt-utils && \
    apt-get install -y --force-yes \
    curl gcc make sudo expect gnupg fakeroot perl-base=5.14.2-21+deb7u3 perl \
    libc-bin=2.13-38+deb7u10 libc6=2.13-38+deb7u10 libc6-dev build-essential \
    cdbs devscripts equivs automake autoconf libtool libaudit-dev selinux-basics \
    libdb5.1=5.1.29-5 libdb5.1-dev libssl1.0.0=1.0.1e-2+deb7u20 procps gawk libsigsegv2

# Add Debian's source repository and, Install NodeJS 6
RUN apt-get update && apt-get build-dep python3.2 -y && \
    curl -sL https://deb.nodesource.com/setup_6.x | bash -

RUN sed -i 's:https:http:g' /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install nodejs -y

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
