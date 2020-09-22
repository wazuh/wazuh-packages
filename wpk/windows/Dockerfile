FROM debian:9

RUN apt-get update && \
    apt-get -y install \
      python \
      git \
      curl \
      jq && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py && \
    pip install --upgrade cryptography awscli

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
VOLUME /var/local/wazuh
VOLUME /etc/wazuh
VOLUME /etc/wazuh/checksum
ENTRYPOINT ["/usr/local/bin/run"]
