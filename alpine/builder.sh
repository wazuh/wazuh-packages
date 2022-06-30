#!/bin/bash

# Wazuh package builder
# Copyright (C) 2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
export target="wazuh-agent"
export directory_base="/var/ossec"
export architecture=$1
export revision=$2
export reference=$3
spec_reference=$5
future=$4

if [ -z "${revision}" ]; then
    export revision="1"
fi

if [ "${future}" = "yes" ];then
    export version="99.99.0"
else
    if [ "${spec_reference}" ];then
        export version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/VERSION | cat)
    else
        export version=$(cat /root/VERSION)
    fi
fi

# Build directories
build_dir=/build
spec_path="${build_dir}/SPECS"
file_name="${target}-${version}-r${revision}"
pkg_path="/root/packages/SPECS/${architecture}"
pkg_file="${file_name}.apk"
mkdir -p ${spec_path}

# Including spec file
if [ "${spec_reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${spec_reference} | tar zx
    cp -r ./wazuh*/alpine/SPECS/${target} ${spec_path}/
else
    cp -r /root/alpine/SPECS/${target} ${spec_path}/
fi

# Building APK
cd ${spec_path}/${target}
abuild-keygen -a -i -n
abuild -F checksum
abuild -F -r

cd ${pkg_path} && sha512sum ${pkg_file} > /tmp/${pkg_file}.sha512
find ${pkg_path}/ -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /tmp/ \;
