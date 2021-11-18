FROM debian:buster

LABEL "com.github.actions.name"="unattended-aio-debian-buster"
LABEL "com.github.actions.description"="Test unattended installer All-In-One Debian Buster"

LABEL "name"="Validate unattended installer"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-packages"
LABEL "maintainer"="Wazuh"

ENV DEBIAN_FRONTEND=noninteractive

USER root
WORKDIR /root

RUN apt-get update && apt-get upgrade && \ 
    apt-get install -y \
        openssl \
        apt-utils \
        sudo \
        awscli \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        make \
        gnupg2 \
        apt-transport-https \
        gcc \
        zlib1g-dev \
        libssl-dev \
        libffi-dev \
        perl \
        procps

RUN cd /usr/local/src/ && \ 
    curl https://www.openssl.org/source/openssl-1.1.1g.tar.gz | tar -xz && \
    cd openssl-1.1.1g && ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    make && make test && make install && cd /etc/ld.so.conf.d/ && echo "/usr/local/ssl/lib" > openssl-1.1.1c.conf && \
    ldconfig -v && \ 
    echo 'OPENSSL_PATH="/usr/local/ssl/bin"' > /etc/profile.d/openssl.sh && \
    echo 'export OPENSSL_PATH' > /etc/profile.d/openssl.sh && \
    echo 'PATH=$PATH:$OPENSSL_PATH' > /etc/profile.d/openssl.sh && \
    echo 'export PATH' > /etc/profile.d/openssl.sh && \
    chmod +x /etc/profile.d/openssl.sh && . /etc/profile.d/openssl.sh

RUN curl https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz | tar xz && \
    cd Python-3.8.2 && \
    ./configure --prefix=/usr/testing --enable-optimizations && \
    make install -j 4 && \
    make clean && \
    /usr/testing/bin/pip3 install pytest==5.4.1 tools pyyaml requests && \
    cd .. && \
    rm -rf /Python-3.8.2

COPY ./entrypoint.sh /entrypoint.sh
COPY ./test_unattended.py /test_unattended.py 
COPY ./pytest.ini /pytest.ini
RUN chmod 755 /entrypoint.sh 
