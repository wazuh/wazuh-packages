#!/bin/bash

wazuh_branch=$1
checksum=$2
revision=$3

wazuh_version=""
splunk_version=""

build_dir="/pkg"
destination_dir="/wazuh_splunk_app"
checksum_dir="/var/local/checksum"
package_conf="${build_dir}/SplunkAppForWazuh/default/package.conf"

download_sources() {
    if ! curl -L https://github.com/wazuh/wazuh-splunk/tarball/${wazuh_branch} | tar zx ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi
    mv wazuh-* ${build_dir}
    wazuh_version=$(cat ${package_conf} | grep version -m 1 | cut -d ' ' -f 3)
    splunk_version=$(cat ${package_conf} | grep version -m 3 | cut -d ' ' -f 3 | head -n 3 | tail -1)
}


build_package() {

    download_sources

    cd ${build_dir}

    if [ -z ${revision} ]; then
        wazuh_splunk_pkg_name="wazuhapp-splunk-${wazuh_version}_${splunk_version}.tar.gz"
    else
        wazuh_splunk_pkg_name="wazuhapp-splunk-${wazuh_version}_${splunk_version}_${revision}.tar.gz"
    fi

    tar -zcf ${wazuh_splunk_pkg_name} SplunkAppForWazuh

    mv ${wazuh_splunk_pkg_name} ${destination_dir}

    if [ ${checksum} = "yes" ]; then
        cd ${destination_dir} && sha512sum "${wazuh_splunk_pkg_name}" > "${checksum_dir}/${wazuh_splunk_pkg_name}".sha512
    fi

    exit 0
}

build_package