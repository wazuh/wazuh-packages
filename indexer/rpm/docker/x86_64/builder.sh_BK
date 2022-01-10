#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
# Optional package release
target="wazuh-indexer"
architecture=$1
release=$2
directory_base=$3
version="4.3.0"
rpmbuild="rpmbuild"

if [ -z "${release}" ]; then
    release="1"
fi


# Build directories
build_dir=/build
rpm_build_dir=${build_dir}/rpmbuild
file_name="${target}-${version}-${release}"
pkg_path="${rpm_build_dir}/RPMS/${architecture}"
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the sources directory to build the source tar.gz
package_name=${target}-${version}
mkdir ${build_dir}/${package_name}
#files_dir="${build_dir}/${package_name}"
#curl -kOL https://s3.amazonaws.com/warehouse.wazuh.com/indexer/opensearch-1.2.1-linux-x64.tar.gz
#tar xzvf opensearch-*.tar.gz && rm -f opensearch-*.tar.gz
#find opensearch-* -type l -exec rm -f {} \;
#rm -rf opensearch-*/jdk/conf/security/policy/unlimited
#rm -f opensearch-*/performance-analyzer-rca/bin/performance-analyzer-rca.bat
#mv -f opensearch-* ${files_dir}

# Including spec file
cp /root/${target}.spec ${rpm_build_dir}/SPECS/${package_name}.spec

# Generating source tar.gz
cd ${build_dir} && tar czf "${rpm_build_dir}/SOURCES/${package_name}.tar.gz" "${package_name}"

# Building RPM
/usr/bin/rpmbuild --define "_topdir ${rpm_build_dir}" \
    --define "_release ${release}" --define "_localstatedir ${directory_base}" \
    --target ${architecture} -ba ${rpm_build_dir}/SPECS/${package_name}.spec

find ${pkg_path}/ -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /tmp/ \;
