#!/bin/bash

set -exf

# Script parameters to build the package
build_target=$1
wazuh_version=$2
architecture_target=$3
package_release=$4
package_full_name="wazuh-${build_target}-${wazuh_version}"

if [ -z "${package_release}" ]; then
    package_release="1"
fi

# Build directories
build_dir=/build_wazuh
source_dir=${build_dir}/source_wazuh

# Generating directory structure to build the .deb package
cd ${build_dir}/${build_target} && tar -czvf ${package_full_name}.orig.tar.gz "${package_full_name}"
cp -pr /${build_target}/debian ${build_dir}/${build_target}/${package_full_name}/debian

# Installing build dependencies
cd ${build_dir}/${build_target}/${package_full_name}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
if [[ "${architecture_target}" == "amd64" ]]; then
    debuild -b -uc -us
else
    linux32 debuild -ai386 -b -uc -us
fi

find ${build_dir} -name "*.deb" -exec mv {} /var/local/wazuh \;