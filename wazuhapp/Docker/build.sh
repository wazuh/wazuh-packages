#!/bin/bash

set -ex

wazuh_branch=$1
checksum=$2
app_revision=$3

kibana_dir="/tmp/source"
source_dir="${kibana_dir}/plugins/wazuh"
build_dir="${source_dir}/build"
destination_dir="/wazuh_app"
checksum_dir="/var/local/checksum"
github_raw_url="https://raw.githubusercontent.com/wazuh/wazuh-kibana-app"
package_json_url="${github_raw_url}/${wazuh_branch}/package.json"

export package_json="${source_dir}/package.json"

wazuh_version=""
kibana_version=""
node_version=""

prepare_env() {
    echo "Download package.json"

    if ! curl -O ${package_json_url} ; then
        echo "Error downloading package.json from GitHub."
        exit 1
    fi

    wazuh_version=$(python -c 'import json, os; f=open("/package.json"); pkg=json.load(f); f.close(); print(pkg["version"])')
    kibana_version=$(python -c 'import json, os; f=open("/package.json"); pkg=json.load(f); f.close(); print(pkg["kibana"]["version"])')

    {
        node_version=$(python -c 'import json, os; f=open("/package.json"); pkg=json.load(f); f.close(); print(pkg["node_build"])')
    }||{
        node_version=$(python -c 'import json, os; f=open("/package.json"); pkg=json.load(f); f.close(); print(pkg["node"])')
    }||{
        node_version="8.14.0"
    }

}

download_sources() {



    if ! curl -L https://github.com/elastic/kibana/tarball/v${kibana_version} | tar zx ; then
        echo "Error downloading Kibana source code from GitHub."
        exit 1
    fi

    mv elastic-* kibana_source
    mkdir -p kibana_source/plugins

    if ! git clone https://github.com/wazuh/wazuh-kibana-app.git --branch ${wazuh_branch} --depth=1 kibana_source/plugins/wazuh ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi

    mv kibana_source ${kibana_dir}
}

install_dependencies (){

    n ${node_version}

    installed_node_version="$(node -v)"

    if [[ "${installed_node_version}" != "v${node_version}" ]]; then
        mv /usr/local/bin/node /usr/bin
        mv /usr/local/bin/npm /usr/bin
        mv /usr/local/bin/npx /usr/bin
    fi
}

build_package(){

    unset NODE_ENV

    cd ${source_dir}

    # Set pkg name
    if [ -z "${app_revision}" ]; then
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}.zip"
    else
        wazuh_app_pkg_name="wazuhapp-${wazuh_version}_${kibana_version}_${app_revision}.zip"
    fi

    # Build the package
    yarn
    yarn build

    find ${build_dir} -name "*.zip" -exec mv {} ${destination_dir}/${wazuh_app_pkg_name} \;

    if [ "${checksum}" = "yes" ]; then
        cd ${destination_dir} && sha512sum "${wazuh_app_pkg_name}" > "${checksum_dir}/${wazuh_app_pkg_name}".sha512
    fi

    exit 0
}

prepare_env
download_sources
install_dependencies
build_package
