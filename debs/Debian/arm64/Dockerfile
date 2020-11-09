FROM arm64v8/debian:stretch

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://deb.debian.org/debian stretch contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y apt apt-utils  \
    curl gcc make sudo expect gnupg \
    perl-base perl wget libc-bin libc6 libc6-dev \
    build-essential cdbs devscripts equivs automake \
    autoconf libtool libaudit-dev selinux-basics \
    libdb5.3 libdb5.3 libssl1.0.2 gawk libsigsegv2

# Add Debian's source repository and, Install NodeJS 12
RUN apt-get update &&  apt-get build-dep python3.5 -y
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    apt-get install -y nodejs

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-5.5.0.tar.gz && \
    tar xzf gcc-5.5.0.tar.gz  && cd gcc-5.5.0/ && \
    ./contrib/download_prerequisites && \
    ./configure --prefix=/usr/local/gcc-5.5.0 --enable-languages=c,c++ --disable-multilib --disable-libsanitizer --disable-bootstrap && \
    make -j$(nproc) && make install && \
    ln -fs /usr/local/gcc-5.5.0/bin/gcc /usr/bin/cc && \
    ln -fs /usr/local/gcc-5.5.0/bin/g++ /usr/bin/c++ && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-5.5.0/include/c++/5.5.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-5.5.0/lib64/"
ENV PATH "/usr/local/gcc-5.5.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxvf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    ./bootstrap CC=/usr/local/gcc-5.5.0/bin/gcc CXX=/usr/local/gcc-5.5.0/bin/g++ && \
    make -j$(nproc) && make install && ln -s /usr/local/bin/cmake /usr/bin/cmake && \
    cd / && rm -rf cmake-*

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
