FROM ubuntu:bionic
RUN export DEBIAN_FRONTEND="noninteractive" \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        gcc-mingw-w64 \
        git \
        nsis\
        dos2unix\
        binutils
RUN mkdir /home/wazuh_msi
RUN mkdir /home/wazuh_msi/output

VOLUME /home/wazuh_msi
VOLUME /home/wazuh_msi/output

COPY entrypoint.sh /home/wazuh_msi/
WORKDIR /home/wazuh_msi
RUN dos2unix entrypoint.sh

ENTRYPOINT [ "/home/wazuh_msi/entrypoint.sh" ]