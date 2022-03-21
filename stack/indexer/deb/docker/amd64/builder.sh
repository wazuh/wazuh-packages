#!/bin/bash

# Wazuh indexer builder
# Copyright (C) 2021, Wazuh Inc.
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
base_location=$4
spec_reference=$5
directory_base="/usr/share/wazuh-indexer"

if [ -z "${release}" ]; then
    release="1"
fi

if [ "${future}" = "yes" ];then
    version="99.99.0"
else
    if [ "${spec_reference}" ];then
        version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/VERSION | cat)
    else
        version=$(cat /root/VERSION)
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
    cp -r ./wazuh*/stack/indexer/deb/debian/* ${sources_dir}/debian/
    cp -r ./wazuh*/* /root/
else
    cp -r /root/stack/indexer/deb/debian/* ${sources_dir}/debian/
fi

# Generating directory structure to build the .deb package
cd ${build_dir}/${target} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s:VERSION:${version}:g" ${sources_dir}/debian/changelog
sed -i "s:RELEASE:${release}:g" ${sources_dir}/debian/changelog

# Installing build dependencies
cd ${sources_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild --no-lintian -eINSTALLATION_DIR="${directory_base}" -eBASE="${base_location}" -eBASE_VERSION="${version}" -b -uc -us

deb_file="${target}_${version}-${release}_${architecture}.deb"

cd ${pkg_path} && sha512sum ${deb_file} > /tmp/${deb_file}.sha512

mv ${pkg_path}/${deb_file} /tmp/
