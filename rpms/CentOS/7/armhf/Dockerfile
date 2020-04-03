FROM arm32v7/centos:7

ADD build_deps.sh /build_deps.sh
RUN sh build_deps.sh

RUN curl -O https://nodejs.org/dist/v12.16.1/node-v12.16.1-linux-armv7l.tar.xz && \
    tar -xJf node-v12.16.1-linux-armv7l.tar.xz && cd node-v12.16.1-linux-armv7l && cp -R * /usr/local/

# Update rpmbuild, rpm and autoconf
RUN curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && ./configure && make && make install

RUN curl -O https://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    ./configure --without-lua && make && make install

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb

RUN rm -rf autoconf-* rpm-* libarchive-* /root/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]