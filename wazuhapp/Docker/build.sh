#!/bin/bash

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
    cd ${source_dir}
    # Set pkg name
    if [ -z ${app_revision} ]; then
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}.zip"
    else
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}_${app_revision}.zip"
    fi
    yarn
    yarn build
    if [[ "${checksum}" == "yes" ]]; then
        find ${build_dir} -name "*.zip" -exec mv {} ${destination_dir}/${wazuh_app_pkg_name} \;
        find ${destination_dir} -name "*.zip" -exec bash -c 'cd $(dirname {}) && sha512sum $(basename {}) > {}.sha512' \;
    else
        find ${build_dir} -name "*.zip" -exec mv {} ${destination_dir}/${wazuh_app_pkg_name} \;
    fi
}

wazuh_version=$1
kibana_version=$2
if [ -z $4 ]; then
    checksum=$3
else
    app_revision=$3
    checksum=$4
fi

source_dir="/source"
build_dir="${source_dir}/build"
destination_dir="/wazuh_app"

install_dependencies
build_package
