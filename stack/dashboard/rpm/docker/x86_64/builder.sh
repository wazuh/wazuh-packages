#!/bin/bash

# Wazuh package builder
# Copyright (C) 2021, Wazuh Inc.
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
future=$3
base_location=$4
spec_reference=$5
directory_base="/usr/share/wazuh-dashboard"
rpmbuild="rpmbuild"

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
rpm_build_dir=${build_dir}/rpmbuild
file_name="${target}-${version}-${release}"
pkg_path="${rpm_build_dir}/RPMS/${architecture}"
rpm_file="${file_name}.${architecture}.rpm"
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the sources directory to build the source tar.gz
pkg_name=${target}-${version}
mkdir ${build_dir}/${pkg_name}


# Including spec file
if [ "${spec_reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${spec_reference} | tar zx
    cp ./wazuh*/stack/dashboard/rpm/${target}.spec ${rpm_build_dir}/SPECS/${pkg_name}.spec
    cp -r ./wazuh*/* /root/
else
    cp /root/stack/dashboard/rpm/${target}.spec ${rpm_build_dir}/SPECS/${pkg_name}.spec
fi


# Generating source tar.gz
cd ${build_dir} && tar czf "${rpm_build_dir}/SOURCES/${pkg_name}.tar.gz" "${pkg_name}"

# Building RPM
/usr/bin/rpmbuild --define "_topdir ${rpm_build_dir}" --define "_version ${version}" \
    --define "_release ${release}" --define "_localstatedir ${directory_base}" \
    --define "_base ${base_location}" \
    --target ${architecture} -ba ${rpm_build_dir}/SPECS/${pkg_name}.spec

cd ${pkg_path} && sha512sum ${rpm_file} > /tmp/${rpm_file}.sha512


find ${pkg_path}/ -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /tmp/ \;