#!/bin/bash

wazuh_version=$1
kibana_version=$2
if [ -z $4 ]; then
    checksum=$3
else
    app_revision=$3
    checksum=$4
fi

orig_source_dir="/source"
source_dir="/tmp/source"
build_dir="${source_dir}/build"
destination_dir="/wazuh_app"
checksum_dir="/var/local/checksum"

install_dependencies (){

    {
        node_version=$(python -c 'import json; f=open("/source/package.json"); pkg=json.load(f); f.close(); print(pkg["node_build"])')
    }||{
        node_version=$(python -c 'import json; f=open("/source/package.json"); pkg=json.load(f); f.close(); print(pkg["node"])')
    }||{
        node_version="8.14.0"
    }

    n ${node_version}

    installed_node_version="$(node -v)"

    if [[ "${installed_node_version}" == "v${node_version}" ]]; then
        mv /usr/local/bin/node /usr/bin
        mv /usr/local/bin/npm /usr/bin
        mv /usr/local/bin/npx /usr/bin
    fi
}

build_package(){

    unset NODE_ENV
    cp -r ${orig_source_dir} ${source_dir}
    cd ${source_dir}
    # Set pkg name
    if [ -z ${app_revision} ]; then
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}.zip"
    else
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}_${app_revision}.zip"
    fi
    yarn
    yarn build

    find ${build_dir} -name "*.zip" -exec mv {} ${destination_dir}/${wazuh_app_pkg_name} \;

    if [[ "${checksum}" == "yes" ]]; then
        cd ${destination_dir} && sha512sum "${wazuh_app_pkg_name}" > "${checksum_dir}/${wazuh_app_pkg_name}".sha512
    fi

    rm -rf ${source_dir}
}

install_dependencies
build_package
