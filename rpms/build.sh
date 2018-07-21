#!/bin/bash

set -exf
# Optional package release
build_target=$1
wazuh_version=$2
architecture_target=$3
package_release=$4
if [ -z "${package_release}" ]; then
    package_release="1"
fi

# Build directories
build_dir=/build_wazuh
rpm_build_dir=${build_dir}/rpmbuild
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Generating source tar.gz
package_name=wazuh-${build_target}-${wazuh_version}
cd ${build_dir} && tar cvzf "${rpm_build_dir}/SOURCES/${package_name}.tar.gz" "${package_name}"

# Including spec file
sed -i "s/Release:     .*/Release:     ${package_release}/g" ${build_dir}/wazuh.spec
mv ${build_dir}/wazuh.spec ${rpm_build_dir}/SPECS/${package_name}.spec

if [ "${architecture_target}" == "i386" ]; then
    linux="linux32"
fi

# Building RPM
$linux rpmbuild --define "_topdir ${rpm_build_dir}" --target ${architecture_target} \
    -ba ${rpm_build_dir}/SPECS/${package_name}.spec
find ${rpm_build_dir} -name "*.rpm" -exec mv {} /var/local/wazuh \;
