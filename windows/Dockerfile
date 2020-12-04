FROM ubuntu:18.04

# Installing necessary packages
RUN apt-get update && \
    apt-get install -y gcc g++ gcc-mingw-w64 g++-mingw-w64 nsis make wget unzip \
    curl perl binutils zip libssl1.1 libssl-dev

ADD entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
