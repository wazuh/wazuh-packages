FROM debian:9

RUN apt-get update && \
    apt-get -y install python git curl jq python3 python3-pip && \
    pip3 install --upgrade cryptography==2.9.2 awscli

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
VOLUME /var/local/wazuh
VOLUME /etc/wazuh
VOLUME /etc/wazuh/checksum
ENTRYPOINT ["/usr/local/bin/run"]
