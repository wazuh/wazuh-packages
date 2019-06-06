#!/bin/bash

build_package() {

    cd /pkg
    tar -zcvf ${wazuh_splunk_pkg_name} SplunkAppForWazuh
    if [[ $CHECKSUM == "yes"]]; then
         sha512sum "${wazuh_splunk_pkg_name}" > "${wazuh_splunk_pkg_name}".sha512
    fi
    mv ${wazuh_splunk_pkg_name}.* ../wazuh_splunk_app
    cd ..
}
if [ $3 == "" ]; then
    wazuh_splunk_pkg_name="SplunkAppForWazuh_v${wazuh_version}_${splunk_version}.tar.gz"
else
    wazuh_splunk_pkg_name="SplunkAppForWazuh_v${wazuh_version}_${splunk_version}_${REVISION}.tar.gz"
fi

WAZUH_VERSION=$1
SPLUNK_VERSION=$2
REVISION=$3
CHECKSUM=$4
build_package
