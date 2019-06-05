#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -exf

# Script parameters to build the package
build_target=$1
wazuh_version=$2
architecture_target=$3
package_release=$4
jobs=$5
dir_path=$6
debug=$7
checksum=$8
package_full_name="wazuh-${build_target}-${wazuh_version}"

if [ -z "${package_release}" ]; then
    package_release="1"
fi

# Build directories
build_dir=/build_wazuh
source_dir=${build_dir}/source_wazuh

# Generating directory structure to build the .deb package
cd ${build_dir}/${build_target} && tar -czf ${package_full_name}.orig.tar.gz "${package_full_name}"
cp -pr /${build_target}/debian ${build_dir}/${build_target}/${package_full_name}/debian

# Configure the package with the different parameters
sed -i "s:RELEASE:${package_release}:g" ${build_dir}/${build_target}/${package_full_name}/debian/changelog
sed -i "s:export JOBS=.*:export JOBS=${jobs}:g" ${build_dir}/${build_target}/${package_full_name}/debian/rules
sed -i "s:export DEBUG_ENABLED=.*:export DEBUG_ENABLED=${debug}:g" ${build_dir}/${build_target}/${package_full_name}/debian/rules
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${dir_path}:g" ${build_dir}/${build_target}/${package_full_name}/debian/rules
sed -i "s:DIR=\"/var/ossec\":DIR=\"${dir_path}\":g" ${build_dir}/${build_target}/${package_full_name}/debian/{preinst,postinst,prerm,postrm}
if [ "${build_target}" == "api" ]; then
    sed -i "s:DIR=\"/var/ossec\":DIR=\"${dir_path}\":g" ${build_dir}/${build_target}/${package_full_name}/debian/wazuh-api.init
fi

# Installing build dependencies
cd ${build_dir}/${build_target}/${package_full_name}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
if [[ "${architecture_target}" == "amd64" ]]; then
    debuild -b -uc -us
else
    linux32 debuild -ai386 -b -uc -us
fi

if [[ "${checksum}" == "yes" ]]; then
    find ${build_dir} -name "*.deb" -exec bash -c 'sha512sum "$1" > "$1".sha512' bash {} \;
    find ${build_dir} -name "*.deb.sha512" -exec mv {} /var/local/wazuh \;
fi

find ${build_dir} -name "*.deb" -exec mv {} /var/local/wazuh \;
