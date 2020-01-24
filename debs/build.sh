#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
build_target=$1
wazuh_branch=$2
architecture_target=$3
package_release=$4
jobs=$5
dir_path=$6
debug=$7
checksum=$8
wazuh_packages_branch=$9
use_local_specs=${10}

if [ -z "${package_release}" ]; then
    package_release="1"
fi

if [ ${build_target} = "api" ]; then
    curl -sL https://github.com/wazuh/wazuh-api/tarball/${wazuh_branch} | tar zx
    wazuh_version="$(grep version wazuh*/package.json | cut -d '"' -f 4)"
else
    curl -sL https://github.com/wazuh/wazuh/tarball/${wazuh_branch} | tar zx
    wazuh_version="$(cat wazuh*/src/VERSION | cut -d 'v' -f 2)"
fi

# Build directories
build_dir=/build_wazuh
package_full_name="wazuh-${build_target}-${wazuh_version}"
sources_dir="${build_dir}/${build_target}/${package_full_name}"

mkdir -p ${build_dir}/${build_target}
mv wazuh* ${build_dir}/${build_target}/wazuh-${build_target}-${wazuh_version}

if [ "${use_local_specs}" = "no" ]; then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${wazuh_packages_branch} | tar zx
    package_files="wazuh*/debs"
    specs_path="${package_files}/SPECS"
else
    package_files="/specs"
    specs_path="${package_files}/SPECS"
fi
cp -pr ${specs_path}/${wazuh_version}/wazuh-${build_target}/debian ${sources_dir}/debian
cp -p ${package_files}/gen_permissions.sh ${sources_dir}

# Generating directory structure to build the .deb package
cd ${build_dir}/${build_target} && tar -czf ${package_full_name}.orig.tar.gz "${package_full_name}"

# Configure the package with the different parameters
sed -i "s:RELEASE:${package_release}:g" ${sources_dir}/debian/changelog
sed -i "s:export JOBS=.*:export JOBS=${jobs}:g" ${sources_dir}/debian/rules
sed -i "s:export DEBUG_ENABLED=.*:export DEBUG_ENABLED=${debug}:g" ${sources_dir}/debian/rules
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${dir_path}:g" ${sources_dir}/debian/rules
sed -i "s:DIR=\"/var/ossec\":DIR=\"${dir_path}\":g" ${sources_dir}/debian/{preinst,postinst,prerm,postrm}
if [ "${build_target}" == "api" ]; then
    sed -i "s:DIR=\"/var/ossec\":DIR=\"${dir_path}\":g" ${sources_dir}/debian/wazuh-api.init
    if [ "${architecture_target}" == "ppc64le" ]; then
        sed -i "s: nodejs (>= 4.6), npm,::g" ${sources_dir}/debian/control
    fi
fi

if [[ "${debug}" == "yes" ]]; then
    sed -i "s:dh_strip --no-automatic-dbgsym::g" ${sources_dir}/debian/rules
fi

# Installing build dependencies
cd ${sources_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
if [[ "${architecture_target}" == "amd64" ]] ||  [[ "${architecture_target}" == "ppc64le" ]] ; then
    debuild -b -uc -us

else
    linux32 debuild -ai386 -b -uc -us
fi

deb_file="wazuh-${build_target}_${wazuh_version}-${package_release}_${architecture_target}.deb"
pkg_path="${build_dir}/${build_target}"

if [[ "${checksum}" == "yes" ]]; then
    cd ${pkg_path} && sha512sum ${deb_file} > /var/local/checksum/${deb_file}.sha512
fi

mv ${pkg_path}/${deb_file} /var/local/wazuh