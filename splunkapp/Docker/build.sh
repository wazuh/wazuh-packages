#!/bin/bash

build_package() {

    cd ${build_dir}

    if [ -z ${REVISION} ]; then
        wazuh_splunk_pkg_name="SplunkAppForWazuh_v${WAZUH_VERSION}_${SPLUNK_VERSION}.tar.gz"
    else
        wazuh_splunk_pkg_name="SplunkAppForWazuh_v${WAZUH_VERSION}_${SPLUNK_VERSION}_${REVISION}.tar.gz"
    fi

    tar -zcf ${wazuh_splunk_pkg_name} SplunkAppForWazuh

    if [[ ${CHECKSUM} == "yes" ]]; then
         sha512sum "${wazuh_splunk_pkg_name}" > "${destination_dir}/${wazuh_splunk_pkg_name}".sha512
    fi

    mv ${wazuh_splunk_pkg_name} ${destination_dir}
}


WAZUH_VERSION=$1
SPLUNK_VERSION=$2
if [ -z $4 ]; then
    CHECKSUM=$3
else
    REVISION=$3
    CHECKSUM=$4
fi

build_dir="/pkg"
destination_dir="/wazuh_splunk_app"

build_package
