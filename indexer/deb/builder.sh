#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
# Script parameters to build the package
target="wazuh-indexer"
architecture=$1
release=$2
future=$3
spec_reference=$4
directory_base="/usr/share/wazuh-indexer"

if [ -z "${release}" ]; then
    release="1"
fi

if [ "${future}" = "yes" ];then
    version="99.99.0"
else
    if [ "${spec_reference}" ];then
        version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/indexer/deb/debian/changelog | egrep -o -m 1 '[0-9]+\.[0-9]+\.[0-9]+')
    else
        version=$(egrep -o -m 1 '[0-9]+\.[0-9]+\.[0-9]+' /root/indexer/deb/debian/changelog)
    fi
fi

# Build directories
build_dir=/build
pkg_name="${target}-${version}"
pkg_path="${build_dir}/${target}"
sources_dir="${pkg_path}/${pkg_name}"

mkdir -p ${sources_dir}/debian

# Including spec file
if [ "${spec_reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${spec_reference} | tar zx
    cp -r ./wazuh*/indexer/deb/debian/* ${sources_dir}/debian/
    cp -r ./wazuh*/* /root/
else
    cp -r /root/indexer/deb/debian/* ${sources_dir}/debian/
fi

if [ "${future}" = "yes" ];then
    sed -i '1s|[0-9]\+.[0-9]\+.[0-9]\+-RELEASE|99.99.0-RELEASE|' ${sources_dir}/debian/changelog
fi

# Generating directory structure to build the .deb package
cd ${build_dir}/${target} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s:RELEASE:${release}:g" ${sources_dir}/debian/changelog
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${directory_base}:g" ${sources_dir}/debian/rules

# Installing build dependencies
cd ${sources_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild -b -uc -us

deb_file="${target}_${version}-${release}_${architecture}.deb"

cd ${pkg_path} && sha512sum ${deb_file} > /tmp/${deb_file}.sha512

mv ${pkg_path}/${deb_file} /tmp/
