FROM ubuntu:bionic
RUN export DEBIAN_FRONTEND="noninteractive" \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        gcc-mingw-w64 \
        git \
        nsis\
        dos2unix\
        binutils \
        ca-certificates \
        unzip \
        curl \
        wget

RUN mkdir /home/wazuh_msi
RUN mkdir /home/wazuh_msi/output

VOLUME /home/wazuh_msi
VOLUME /home/wazuh_msi/output

COPY entrypoint.sh /home/wazuh_msi/
WORKDIR /home/wazuh_msi
RUN  chmod +x /home/wazuh_msi && \
        useradd -ms /bin/bash wazuh-builder

ENTRYPOINT [ "sh","/home/wazuh_msi/entrypoint.sh" ]
