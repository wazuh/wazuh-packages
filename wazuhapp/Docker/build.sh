#!/bin/bash

set -ex

# Script parameters
wazuh_branch=$1
checksum=$2
app_revision=$3

# Paths
build_user_home="/home/builduser"
kibana_dir="/tmp/source"
source_dir="${kibana_dir}/plugins/wazuh"
build_dir="${source_dir}/build"
destination_dir="${build_user_home}/wazuh_app"
checksum_dir="/var/local/checksum"

# Repositories URLs
wazuh_app_clone_repo_url="https://github.com/wazuh/wazuh-kibana-app.git"
wazuh_app_raw_repo_url="https://raw.githubusercontent.com/wazuh/wazuh-kibana-app"
kibana_app_repo_url="https://github.com/elastic/kibana.git"
kibana_app_raw_repo_url="https://raw.githubusercontent.com/elastic/kibana"
wazuh_app_package_json_url="${wazuh_app_raw_repo_url}/${wazuh_branch}/package.json"

# Script vars
wazuh_version=""
kibana_version=""
kibana_yarn_version=""
kibana_node_version=""
export N_PREFIX=$HOME

change_node_version () {
    installed_node_version="$(node -v)"
    node_version=$1

    n ${node_version}

    if [[ "${installed_node_version}" != "v${node_version}" ]]; then
	    export PATH=${build_user_home}/bin:$PATH
	    echo "Updated PATH=${PATH}"
    #    mv /usr/local/bin/node /usr/bin
    #    mv /usr/local/bin/npm /usr/bin
    #    mv /usr/local/bin/npx /usr/bin
    fi

    echo "Using $(node -v) node version"
}


prepare_env() {
    echo "Downloading package.json from wazuh-kibana app repository"
    if ! curl $wazuh_app_package_json_url -o "/tmp/package.json" ; then
        echo "Error downloading package.json from GitHub."
        exit 1
    fi

    wazuh_version=$(python -c 'import json, os; f=open("/tmp/package.json"); pkg=json.load(f); f.close();\
                    print(pkg["version"])')
    kibana_version=$(python -c 'import json, os; f=open("/tmp/package.json"); pkg=json.load(f); f.close();\
                     print(pkg["kibana"]["version"])')

    kibana_package_json_url="${kibana_app_raw_repo_url}/v${kibana_version}/package.json"

    echo "Downloading package.json from elastic/kibana repository"
    if ! curl $kibana_package_json_url -o "/tmp/package.json" ; then
        echo "Error downloading package.json from GitHub."
        exit 1
    fi

    kibana_node_version=$(python -c 'import json, os; f=open("/tmp/package.json"); pkg=json.load(f); f.close();\
                          print(pkg["engines"]["node"])')

    kibana_yarn_version=$(python -c 'import json, os; f=open("/tmp/package.json"); pkg=json.load(f); f.close();\
                          print(pkg["engines"]["yarn"])')
}


download_kibana_sources() {
    if ! git clone $kibana_app_repo_url --branch "v${kibana_version}" --depth=1 kibana_source; then
        echo "Error downloading Kibana source code from elastic/kibana GitHub repository."
        exit 1
    fi
    
    mkdir -p kibana_source/plugins
    mv kibana_source ${kibana_dir}     
}


install_dependencies () {
    cd ${kibana_dir}
    change_node_version $kibana_node_version
    npm install "yarn@${kibana_yarn_version}"
    export PATH=${kibana_dir}/node_modules/yarn/bin:$PATH
    echo "Updated PATH=${PATH}"
    yarn config set network-timeout 600000 -g
    yarn kbn bootstrap --skip-kibana-plugins --oss
}


download_wazuh_app_sources() {
    if ! git clone $wazuh_app_clone_repo_url --branch ${wazuh_branch} --depth=1 ${kibana_dir}/plugins/wazuh ; then
        echo "Error downloading the source code from wazuh-kibana-app GitHub repository."
        exit 1
    fi      
}


build_package(){
   
    cd $source_dir

    # Set pkg name
    if [ -z "${app_revision}" ]; then
        wazuh_app_pkg_name="wazuh_kibana-${wazuh_version}_${kibana_version}.zip"
    else
        wazuh_app_pkg_name="wazuh_kibana-${wazuh_version}_${kibana_version}-${app_revision}.zip"
    fi

    # Build the package
    yarn
    KIBANA_VERSION=${kibana_version} yarn build

    find ${build_dir} -name "*.zip" -exec mv {} ${destination_dir}/${wazuh_app_pkg_name} \;

    if [ "${checksum}" = "yes" ]; then
        cd ${destination_dir} && sha512sum "${wazuh_app_pkg_name}" > "${checksum_dir}/${wazuh_app_pkg_name}".sha512
    fi

    exit 0
}


prepare_env
download_kibana_sources
install_dependencies
download_wazuh_app_sources
build_package
