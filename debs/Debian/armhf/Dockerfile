FROM arm32v7/debian:stretch

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://deb.debian.org/debian stretch contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y apt-utils \
    curl gcc make sudo expect gnupg fakeroot perl-base \
    perl libc-bin libc6 libc6-dev \
    build-essential cdbs devscripts equivs automake autoconf libtool \
    libaudit-dev selinux-basics util-linux libdb5.1 \
    libssl1.1 libssl-dev gawk libsigsegv2 procps libc6-armel-cross

# Add Debian's source repository and, Install NodeJS 12
RUN apt-get build-dep python3.5 -y
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    apt-get install -y nodejs

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]