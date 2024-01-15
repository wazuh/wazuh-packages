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
keypath="/root/.abuild"
export target="wazuh-agent"
export reference=$1
export architecture=$2
export revision=$3
export jobs=$4
export directory_base=$5
export debug=$6
spec_reference=$7
local_spec=$8
local_source=$9
future=${10}
aws_region=${11}
private_key_id=${12}
public_key_id=${13}
# Build directories
build_dir=/build
spec_path="${build_dir}/SPECS"
mkdir -p ${spec_path}

if [ -z "${revision}" ]; then
    export revision="1"
fi

if [ "${local_source}" = "no" ]; then
    curl -sL https://github.com/wazuh/wazuh/tarball/${reference} | tar zx
fi
export version="$(cat wazuh*/src/VERSION | cut -d 'v' -f 2)"

if [ "${future}" = "yes" ]; then
    old_version=$version
    MAJOR=$(echo $version | cut -dv -f2 | cut -d. -f1)
    export version="${MAJOR}.30.0"
    sed -i "s/${old_version}/${version}/g" "/wazuh"*"/src/init/wazuh-server.sh"
    sed -i "s/${old_version}/${version}/g" "/wazuh"*"/src/init/wazuh-client.sh"
    sed -i "s/${old_version}/${version}/g" "/wazuh"*"/src/init/wazuh-local.sh"
fi


# Getting the signing key
if [ -n "${private_key_id}" ] && [ -n "${public_key_id}" ]; then
    mkdir -p ${keypath}
    aws --region=${aws_region} secretsmanager get-secret-value --secret-id ${public_key_id} | jq . > public.key.json
    jq .SecretString public.key.json | tr -d '"' | sed 's|\\n|\n|g' > ${keypath}/priv.rsa.pub
    aws --region=${aws_region} secretsmanager get-secret-value --secret-id ${private_key_id} | jq . > private.key.json
    jq .SecretString private.key.json | tr -d '"' | sed 's|\\n|\n|g' > ${keypath}/priv.rsa
    echo 'PACKAGER_PRIVKEY="/root/.abuild/priv.rsa"' > ${keypath}/abuild.conf
    rm -f private.key.json public.key.json
else
    # Use an auto-generated key to sign Alpine package
    abuild-keygen -a -i -n
fi

# Output variables
file_name="${target}-${version}-r${revision}"
pkg_path="/root/packages/SPECS/${architecture}"
pkg_file="${file_name}.apk"

# Including spec file
if [ "${local_spec}" = "no" ]; then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${spec_reference} | tar zx
    cp -r ./wazuh*/alpine/SPECS/${target} ${spec_path}/
else
    cp -r /root/repository/alpine/SPECS/${target} ${spec_path}/
fi

# Building APK
cd ${spec_path}/${target}
if [ "${architecture}" = "x86" ] || [ "${architecture}" = "armhf" ] || \
    [ "${architecture}" = "armv7" ]; then
    linux32 abuild -F checksum
    linux32 abuild -F -r
else
    abuild -F checksum
    abuild -F -r
fi

cd ${pkg_path} && sha512sum ${pkg_file} > /var/local/wazuh/${pkg_file}.sha512
find ${pkg_path}/ -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /var/local/wazuh/ \;
