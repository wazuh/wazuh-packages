#!/bin/bash

# Wazuh package builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e
# Script parameters to build the package
target="wazuh-dashboard"
architecture=$1
revision=$2
future=$3
app_url=$4
plugin_main=$5
plugin_updates=$6
plugin_core=$7
reference=$8
directory_base="/usr/share/wazuh-dashboard"

if [ -z "${revision}" ]; then
    revision="1"
fi

if [ "${future}" = "yes" ];then
    version="99.99.0"
else
    if [ "${reference}" ];then
        version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${reference}/VERSION | cat)
    else
        version=$(cat /root/VERSION)
    fi
fi

if [ "${app_url}" ];then
    valid_url='(https?|ftp|file)://[-[:alnum:]\+&@#/%?=~_|!:,.;]*[-[:alnum:]\+&@#/%=~_|]'
    if [[ $app_url =~ $valid_url ]];then
        if ! curl --output /dev/null --silent --head --fail "${app_url}/${plugin_main}"; then
            echo "The given URL to download the Wazuh main plugin ZIP does not exist: ${app_url}/${plugin_main}"
            exit 1
        fi
        if ! curl --output /dev/null --silent --head --fail "${app_url}/${plugin_updates}"; then
            echo "The given URL to download the Wazuh Check Updates plugin ZIP does not exist: ${app_url}/${plugin_updates}"
            exit 1
        fi
        if ! curl --output /dev/null --silent --head --fail "${app_url}/${plugin_core}"; then
            echo "The given URL to download the Wazuh Core plugin ZIP does not exist: ${app_url}/${plugin_core}"
            exit 1
        fi
    else
        url_main="https://packages-dev.wazuh.com/${app_url}/ui/dashboard/wazuh-${version}-${revision}.zip"
        url_updates="https://packages-dev.wazuh.com/${app_url}/ui/dashboard/wazuhCheckUpdates-${version}-${revision}.zip"
        url_core="https://packages-dev.wazuh.com/${app_url}/ui/dashboard/wazuhCore-${version}-${revision}.zip"
    fi
else
    url_main="https://packages-dev.wazuh.com/pre-release/ui/dashboard/wazuh-${version}-${revision}.zip"
    url_updates="https://packages-dev.wazuh.com/pre-release/ui/dashboard/wazuhCheckUpdates-${version}-${revision}.zip"
    url_core="https://packages-dev.wazuh.com/pre-release/ui/dashboard/wazuhCore-${version}-${revision}.zip"
fi

# Build directories
build_dir=/build
pkg_name="${target}-${version}"
pkg_path="${build_dir}/${target}"
source_dir="${pkg_path}/${pkg_name}"

mkdir -p ${source_dir}/debian

# Including spec file
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${reference} | tar zx
    cp -r ./wazuh*/stack/dashboard/deb/debian/* ${source_dir}/debian/
    cp -r ./wazuh*/* /root/
else
    cp -r /root/stack/dashboard/deb/debian/* ${source_dir}/debian/
fi


# Generating directory structure to build the .deb package
cd ${build_dir}/${target} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s:VERSION:${version}:g" ${source_dir}/debian/changelog
sed -i "s:RELEASE:${revision}:g" ${source_dir}/debian/changelog
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${directory_base}:g" ${source_dir}/debian/rules

# Installing build dependencies
cd ${source_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild --no-lintian -eINSTALLATION_DIR="${directory_base}" -eVERSION="${version}" -eREVISION="${revision}" -eURL="${app_url}" -ePLUGINMAIN="${plugin_main}" -ePLUGINUPDATES="${plugin_updates}" -ePLUGINCORE="${plugin_core}" -b -uc -us

deb_file="${target}_${version}-${revision}_${architecture}.deb"

cd ${pkg_path} && sha512sum ${deb_file} > /tmp/${deb_file}.sha512

mv ${pkg_path}/${deb_file} /tmp/
