#!/bin/bash

install_dependencies (){

    {
        node_version=$(python -c 'import json; f=open("/source/package.json"); pkg=json.load(f); f.close(); print pkg["node_build"]')
    }||{
        node_version=$(python -c 'import json; f=open("/source/package.json"); pkg=json.load(f); f.close(); print pkg["node"]')
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
    cd /source
    # Set pkg name
    if [ ${app_revision} == "" ]; then
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}.zip"
    else
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}_${app_revision}.zip"
    fi
    yarn
    yarn build

    find /source/build/ -name wazuh* -exec cp {} /wazuh_app/${wazuh_app_pkg_name} \;
}

wazuh_version=$1
kibana_version=$2
app_revision=$3

install_dependencies
build_package
