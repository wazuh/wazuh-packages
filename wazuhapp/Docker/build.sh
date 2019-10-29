#!/bin/bash

set -ex

wazuh_branch=$1
checksum=$2
app_revision=$3

source_dir="/tmp/source"
build_dir="${source_dir}/build"
destination_dir="/wazuh_app"
checksum_dir="/var/local/checksum"

export package_json="${source_dir}/package.json"

download_sources() {
    if ! curl -L https://github.com/wazuh/wazuh-kibana-app/tarball/${wazuh_branch} | tar zx ; then
        echo "Error downloading the source code from GitHub."
        exit 1
    fi
    mv wazuh-* ${source_dir}
    wazuh_version=$(python -c 'import json, os; f=open(os.environ["package_json"]); pkg=json.load(f); f.close(); print(pkg["version"])')
    kibana_version=$(python -c 'import json, os; f=open(os.environ["package_json"]); pkg=json.load(f); f.close(); print(pkg["kibana"]["version"])')
}

install_dependencies (){

    {
        node_version=$(python -c 'import json, os; f=open(os.environ["package_json"]); pkg=json.load(f); f.close(); print(pkg["node_build"])')
    }||{
        node_version=$(python -c 'import json, os; f=open(os.environ["package_json"]); pkg=json.load(f); f.close(); print(pkg["node"])')
    }||{
        node_version="8.14.0"
    }

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

download_sources
install_dependencies
build_package
