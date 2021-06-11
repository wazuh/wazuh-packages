#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
# Optional package release
build_target=$1
wazuh_branch=$2
architecture_target=$3
package_release=$4
jobs=$5
dir_path=$6
debug=$7
checksum=$8
wazuh_packages_branch=$9
src=${10}
legacy=${11}
local_source_code=${12}
future=${13}
rpmbuild="rpmbuild"
package_files="/specs"

disable_debug_flag='%debug_package %{nil}'

if [ -z "${package_release}" ]; then
    package_release="1"
fi

if [ "${debug}" = "no" ]; then
    echo ${disable_debug_flag} > /etc/rpm/macros
fi

if [ "${local_source_code}" = "no" ]; then
    curl -sL https://github.com/wazuh/wazuh/tarball/${wazuh_branch} | tar zx
fi
wazuh_version="$(cat wazuh*/src/VERSION | cut -d 'v' -f 2)"

# Build directories
build_dir=/build_wazuh
rpm_build_dir=${build_dir}/${rpmbuild}
file_name="wazuh-${build_target}-${wazuh_version}-${package_release}"
rpm_file="${file_name}.${architecture_target}.rpm"
src_file="${file_name}.src.rpm"
pkg_path="${rpm_build_dir}/RPMS/${architecture_target}"
src_path="${rpm_build_dir}/SRPMS"
extract_path="${pkg_path}"
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SRPMS}

# Prepare the sources directory to build the source tar.gz
package_full_name=wazuh-${build_target}-${wazuh_version}
cp -R wazuh-* ${build_dir}/${package_full_name}
mkdir ${wazuh_version}
cp -R ${package_files}/wazuh-${build_target}-rpms.spec ${wazuh_version}

if [[ "${future}" == "yes" ]]; then    
    # MODIFY VARIABLES
    base_version=${wazuh_version}
    MAJOR=$(echo ${base_version} | cut -dv -f2 | cut -d. -f1)
    MINOR=$(echo ${base_version} | cut -d. -f2)
    wazuh_version="${MAJOR}.30.0"
    file_name="wazuh-${build_target}-${wazuh_version}-${package_release}"
    old_name="wazuh-${build_target}-${base_version}-${package_release}"
    package_full_name=wazuh-${build_target}-${wazuh_version}
    old_package_name=wazuh-${build_target}-${base_version}
    sources_dir="${build_dir}/${package_full_name}"

    # PREPARE FUTURE SPECS AND SOURCES
    mv ${base_version} ${wazuh_version}
    mv ${build_dir}/${old_package_name} ${sources_dir}
    find ${sources_dir} ${wazuh_version} \( -name "*VERSION*" -o -name "*.spec" \) -exec sed -i "s/${base_version}/${wazuh_version}/g" {} \;

fi

cp -pr ${wazuh_version}/wazuh-${build_target}-rpms.spec ${rpm_build_dir}/${package_full_name}.spec

# Generating source tar.gz
cd ${build_dir} && tar czf "${rpm_build_dir}/SOURCES/${package_full_name}.tar.gz" "${package_full_name}"

if [ "${architecture_target}" = "i386" ] || [ "${architecture_target}" = "armv7hl" ]; then
    linux="linux32"
fi

if [ "${legacy}" = "no" ]; then
    echo "%_source_filedigest_algorithm 8" >> /root/.rpmmacros
    echo "%_binary_filedigest_algorithm 8" >> /root/.rpmmacros
    echo " %rhel 6" >> /root/.rpmmacros
    echo " %centos 6" >> /root/.rpmmacros
    echo " %centos_ver 6" >> /root/.rpmmacros
    echo " %dist .el6" >> /root/.rpmmacros
    echo " %el6 1" >> /root/.rpmmacros
    rpmbuild="/usr/local/bin/rpmbuild"
fi

# Building RPM
$linux ${rpmbuild} --define "_sysconfdir /etc" --define "_topdir ${rpm_build_dir}" \
        --define "_threads ${jobs}" --define "_release ${package_release}" \
        --define "_localstatedir ${dir_path}" --define "_debugenabled ${debug}" \
        --target ${architecture_target} -ba ${rpm_build_dir}/${package_full_name}.spec

if [[ "${checksum}" == "yes" ]]; then
    cd ${pkg_path} && sha512sum ${rpm_file} > /var/local/checksum/${rpm_file}.sha512
    if [[ "${src}" == "yes" ]]; then
        cd ${src_path} && sha512sum ${src_file} > /var/local/checksum/${src_file}.sha512
    fi
fi

if [[ "${src}" == "yes" ]]; then
    extract_path="${rpm_build_dir}"
fi

find ${extract_path} -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /var/local/wazuh \;
