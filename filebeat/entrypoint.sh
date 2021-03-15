#!/bin/bash

JOBS=$(nproc)
FILEBEAT_REFERENCE=v7.10.2
FILEBEAT_CONF_URL='https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/filebeat/7.x/filebeat.yml'
OUTPUT_DIR=/pkg
GO_VERSION=1.16.2

# -----------------------------------------------------------------------------

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -v, --version  <filebeat version>    [Required] Filebeat version."
    echo "    -h, --help                           Show this help."
    echo
    exit $1
}


download_go() {
    wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz 
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/usr/local/go
    go version
}

download_filebeat() {
    mkdir -p ${GOPATH}/src/github.com/
    cd ${GOPATH}/src/github.com/
    wget https://github.com/elastic/beats/archive/${FILEBEAT_REFERENCE}.tar.gz
    tar -xzf ${FILEBEAT_REFERENCE}.tar.gz
    mv beats-* filebeat
    cd filebeat/filebeat
    make
    ls -larth
}

get_filebeat() {
    rm -f filebeat.yml
    curl -so filebeat.yml ${FILEBEAT_CONF_URL}
    mkdir bin && mv filebeat ./bin
    tar -czvf filebeat-conf.tar.gz filebeat.reference.yml filebeat.yml modules.d
    tar -czvf filebeat-home.tar.gz ../LICENSE.txt ../NOTICE.txt README.md ./bin ./module
    mv filebeat-home.tar.gz /pkg
    mv filebeat-conf.tar.gz /pkg
}

main () {
   # while [ -n "$1" ]; do
   #     case "$1" in
   #         "-h"|"--help")
   #             help 0
   #         ;;

   #         "-v"|"--version")
   #             if [ -n "$2" ]; then
   #                 FILEBEAT_REFERENCE="$2"
   #                 shift 2
   #             else
   #                 help 1
   #             fi
   #         ;;
   #     esac
   # done

    download_go
    download_filebeat
    get_filebeat
    exit ${EXIT_CODE}
}

main "$@"
