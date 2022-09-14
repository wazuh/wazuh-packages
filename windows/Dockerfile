FROM ubuntu:22.04

# Installing necessary packages
RUN apt-get update && \
    apt-get install -y gcc g++ gcc-mingw-w64 g++-mingw-w64 nsis make wget unzip \
    curl perl binutils zip libssl1.1 libssl-dev lsb-release gnupg

RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt -y install tzdata
RUN dpkg --add-architecture i386
RUN wget -qO - https://dl.winehq.org/wine-builds/winehq.key | apt-key add -
RUN echo "deb https://dl.winehq.org/wine-builds/ubuntu/ $(lsb_release -cs) main" >> /etc/apt/sources.list

RUN apt update
RUN apt install -y --install-recommends winehq-stable
RUN apt install -y winbind

ENV WINEPATH="/usr/i686-w64-mingw32/lib;/path/to/wazuh/src"
ENV WINEARCH=win32

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxvf cmake-3.18.3.tar.gz && \
    cd cmake-3.18.3 && \
    ./bootstrap && make -j$(nproc) && make install && \
    ln -s /usr/local/bin/cmake /usr/bin/cmake && cd / && rm -rf cmake-*

ADD entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
