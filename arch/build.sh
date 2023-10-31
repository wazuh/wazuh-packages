#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
build_target=${1}
wazuh_branch=${2}
architecture_target=${3}
package_release=${4}
jobs=${5}
dir_path=${6}
debug=${7}
checksum=${8}
wazuh_packages_branch=${9}
use_local_specs=${10}
local_source_code=${11}
future=${12}

if [ -z "${package_release}" ]; then
    package_release="1"
fi

if [ "${local_source_code}" = "no" ]; then
    curl -sL https://github.com/wazuh/wazuh/tarball/${wazuh_branch} | tar zx
fi
wazuh_version="$(cat wazuh*/src/VERSION | cut -d 'v' -f 2)"

# Build directories
build_dir=/build_wazuh
package_full_name="wazuh-${build_target}-${wazuh_version}"
sources_dir=`pwd`/"wazuh*"
pacman_dir="${build_dir}/${build_target}/build"

tmp_dir=${build_dir}/tmp
tmp_sources_dir=${tmp_dir}/source

mkdir -p "${pacman_dir}"

if [[ "${use_local_specs}" == "no" ]]; then
    tmp_specs_path=${tmp_dir}/specs
    mkdir -p ${tmp_specs_path}
    cd ${tmp_specs_path}
    specs_path=${tmp_specs_path}
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/${wazuh_packages_branch} | tar zx
    specs_path=`pwd`/$(find . -type d -name "SPECS" -path "*arch*")
    tmp_specs_path=${specs_path}
else
    specs_path="/specs/SPECS"
fi

if [[ "${future}" == "yes" ]]; then
    # MODIFY VARIABLES
    base_version=${wazuh_version}
    MAJOR=$(echo ${base_version} | cut -dv -f2 | cut -d. -f1)
    MINOR=$(echo ${base_version} | cut -d. -f2)
    wazuh_version="${MAJOR}.30.0"
    package_full_name=wazuh-${build_target}-${wazuh_version}

    # PREPARE FUTURE SPECS AND SOURCES
    mkdir -p ${tmp_dir}
    cp -r ${sources_dir} "${tmp_sources_dir}"
    sources_dir="${tmp_sources_dir}"
    find "${sources_dir}" "${specs_path}" \( -name "*VERSION*" -o -name "*changelog*" \) -exec sed -i "s/${base_version}/${wazuh_version}/g" {} \;
    sed -i "s/\$(VERSION)/${MAJOR}.${MINOR}/g" "${sources_dir}/src/Makefile"
    sed -i "s/${base_version}/${wazuh_version}/g" "${sources_dir}/src/init/wazuh-server.sh"
    sed -i "s/${base_version}/${wazuh_version}/g" "${sources_dir}/src/init/wazuh-client.sh"
    sed -i "s/${base_version}/${wazuh_version}/g" "${sources_dir}/src/init/wazuh-local.sh"
fi

cd ${sources_dir} && tar -czf ${pacman_dir}/${package_full_name}.tar.gz . 
cp -pr ${specs_path}/wazuh-${build_target}/arch/* ${pacman_dir}

# Configure the package with the different parameters
sed -i "s:PARAM_VERSION:${wazuh_version}:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_RELEASE:${package_release}:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_SOURCE_FILE:${package_full_name}.tar.gz:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_DEBUG:${debug}:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_INSTALLATION_DIR:${dir_path}:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_INSTALLATION_BACKUP_DIR:`echo ${dir_path} | cut -c 2-`:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_INSTALLATION_SCRIPTS_DIR:${dir_path}/packages_files/agent_installation_scripts:g" ${pacman_dir}/PKGBUILD
sed -i "s:PARAM_JOBS:${jobs}:g" ${pacman_dir}/PKGBUILD

sed -i "s:PARAM_INSTALLATION_DIR:${dir_path}:g" ${pacman_dir}/wazuh.install
sed -i "s:PARAM_INSTALLATION_SCRIPTS_DIR:${dir_path}/packages_files/agent_installation_scripts:g" ${pacman_dir}/wazuh.install

if [[ "${debug}" == "yes" ]]; then
    sed -i "s:dh_strip --no-automatic-dbgsym::g" ${pacman_dir}/PKGBUILD
fi

cd ${pacman_dir}
mkdir ${dir_path}
chmod -R 777 /tmp
chown -R user:user ${dir_path}
chown -R user:user .

# this is an ugly hack
# install.sh will fail in all the user manipulation stuff, but because we changed the user of /var/ossec to be our user, we'll get all the files we need to build the package
# we have to do it that way because install.sh must run as root, and makepkg cannot run as root
mv /usr/bin/{install,real_install}
cat >/usr/bin/install <<EOF
#!/bin/sh

for arg do
    shift
    [[ "\${last_arg}" == "-o" ]] && owner="\${arg}"
    [[ "\${last_arg}" == "-g" ]] && group="\${arg}"
    last_arg="\${arg}"

    [[ "\${dual_arg}" == "1" ]] && dual_arg="0" continue

    # ignore the -o and -g flags
    [[ "\${arg}" == "-o" ]] && dual_arg="1" continue
    [[ "\${arg}" == "-g" ]] && dual_arg="1" continue

    [[ ! "\${arg}" =~ ^-.* ]] && dir="\${arg}"
    set -- "\$@" "\${arg}"
done

if [[ ! "\${owner}" == "" ]]; then
    if [[ ! "\${group}" == "" ]]; then
        owner="\${owner}:\${group}"
    fi
    echo "chown -R \${owner} \${dir}" >> /tmp/fake-install.saved
fi

exec real_install "\$@"
EOF
chmod +x /usr/bin/install

#build the package
su user -c "makepkg -s"
mv /usr/bin/{real_install,install}

# copy the package out
pkg_file="wazuh-${build_target}-${wazuh_version}-${package_release}-${architecture_target}.pkg.tar.zst"
pkg_path="${pacman_dir}"

if [[ "${checksum}" == "yes" ]]; then
    cd ${pkg_path} && sha512sum ${pkg_file} > /var/local/checksum/${pkg_file}.sha512
fi
install -o root -g root ${pkg_path}/${pkg_file} /var/local/wazuh/${pkg_file}
