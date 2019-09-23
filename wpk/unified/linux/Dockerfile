FROM centos:6
ENV PATH=/opt/rh/python27/root/usr/bin:$PATH

RUN yum -y install centos-release-scl && \
    yum -y install gcc make git python27 && \
    echo -e "/opt/rh/python27/root/usr/lib64/" | tee  -a /etc/ld.so.conf && \
    ldconfig && \
    pip install --upgrade pip && \
    pip install --upgrade cryptography

RUN yum install -y automake autoconf libtool
ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ADD gen_versions.sh /usr/local/bin/gen_versions
VOLUME /var/local/wazuh
VOLUME /etc/wazuh
ENTRYPOINT ["/usr/local/bin/run"]
