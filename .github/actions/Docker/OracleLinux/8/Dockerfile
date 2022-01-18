FROM oraclelinux:8

LABEL "com.github.actions.name"="unattended-aio-oraclelinux-8"
LABEL "com.github.actions.description"="Test unattended installer All-In-One Oracle Linux 8"

LABEL "name"="Validate unattended installer"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-packages"
LABEL "maintainer"="Wazuh"

USER root
WORKDIR /root

RUN dnf -y update && \
    dnf -y groupinstall "Development Tools" && \
    dnf install -y \
        openssl \
        gnupg2 \
        sudo \
        ca-certificates \
        curl \
        gnupg \
        redhat-lsb-core  \
        zlib \
        openssl-devel \
        bzip2-devel \
        libffi-devel \
        xz-devel \
        zlib-devel \
        perl-core \
        wget \
        initscripts

RUN rm -f /usr/bin/systemctl

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