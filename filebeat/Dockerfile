ARG ARCHITECTURE=amd64
FROM ${ARCHITECTURE}/centos:7

RUN yum update -y && \
    yum install -y git gcc \
      wget \
      make && \ 
    mkdir /pkg

COPY ./entrypoint.sh /usr/bin/entrypoint.sh
COPY ./wazuh-forwarder.service /pkg

RUN chmod +x /usr/bin/entrypoint.sh

ENTRYPOINT ["/usr/bin/entrypoint.sh"]

CMD ["--help"]

