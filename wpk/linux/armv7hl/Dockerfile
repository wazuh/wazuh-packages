FROM arm32v7/centos:7

ADD build_deps.sh /build_deps.sh
RUN sh build_deps.sh

RUN curl -O https://www.openssl.org/source/openssl-1.1.1g.tar.gz && \
    tar -xzf openssl-1.1.1g.tar.gz && cd openssl* && \
    linux32 ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)' && \
    linux32 make -j $(nproc) && make install && make install

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ADD gen_versions.sh /usr/local/bin/gen_versions

ENTRYPOINT ["linux32 /usr/local/bin/run"]
