#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
# Script parameters to build the package
target="wazuh-dashboard"
architecture=$1
release=$2
directory_base=$3
version="4.3.0"

if [ -z "${release}" ]; then
    release="1"
fi


# Build directories
build_dir=/build
pkg_name="${target}-${version}"
pkg_path="${build_dir}/${target}"
sources_dir="${pkg_path}/${pkg_name}"

mkdir -p ${sources_dir}/debian
#cp -R wazuh-dashboard-* ${sources_dir}

#package_files="/specs"
#specs_path="${package_files}/SPECS"

# Including spec file

cp -r /root/spec/debian/* ${sources_dir}/debian/

#cp -pr ${specs_path}/${version}/${target}/debian ${sources_dir}/debian
#cp -p ${package_files}/gen_permissions.sh ${sources_dir}

# Generating directory structure to build the .deb package
cd ${build_dir}/${target} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s:RELEASE:${release}:g" ${sources_dir}/debian/changelog
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${directory_base}:g" ${sources_dir}/debian/rules
#sed -i "s:DIR=\"/var/ossec\":DIR=\"${directory_base}\":g" ${sources_dir}/debian/{preinst,postinst,prerm,postrm}

# Installing build dependencies
cd ${sources_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild --rootcmd=sudo -b -uc -us

deb_file="${target}_${version}-${release}_${architecture}.deb"

cd ${pkg_path} && sha512sum ${deb_file} > /tmp/${deb_file}.sha512

mv ${pkg_path}/${deb_file} /tmp/