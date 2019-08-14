#!/bin/bash

wazuh_version=$1
splunk_version=$2
if [ -z $4 ]; then
    checksum=$3
else
    revision=$3
    checksum=$4
fi

build_dir="/pkg"
destination_dir="/wazuh_splunk_app"
checksum_dir="/var/local/checksum"


build_package() {

    cd ${build_dir}

    if [ -z ${revision} ]; then
        wazuh_splunk_pkg_name="SplunkAppForWazuh_v${wazuh_version}_${splunk_version}.tar.gz"
    else
        wazuh_splunk_pkg_name="SplunkAppForWazuh_v${wazuh_version}_${splunk_version}_${revision}.tar.gz"
    fi

    tar -zcf ${wazuh_splunk_pkg_name} SplunkAppForWazuh

    mv ${wazuh_splunk_pkg_name} ${destination_dir}

    if [[ ${checksum} == "yes" ]]; then
        cd ${destination_dir} && sha512sum "${wazuh_splunk_pkg_name}" > "${checksum_dir}/${wazuh_splunk_pkg_name}".sha512
    fi
}

build_package