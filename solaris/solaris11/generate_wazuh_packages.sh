#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# Wazuh Solaris 11 Package builder.

REPOSITORY="https://github.com/wazuh/wazuh"
wazuh_branch="master"
install_path="/var/ossec"
THREADS="4"
TARGET="agent"
PATH=$PATH:/opt/csw/bin/
current_path="$( cd $(dirname $0) ; pwd -P )"
arch=`uname -p`
SOURCE=${current_path}/repository
CONFIG="$SOURCE/etc/preloaded-vars.conf"
VERSION=""
target_dir="${current_path}/output"
checksum_dir=""
compute_checksums="no"

trap ctrl_c INT

build_environment() {
    echo "Installing dependencies."

    #Install pkgutil an update
    if [ ! -f  /opt/csw/bin/pkgutil ]; then
        pkgadd -d http://get.opencsw.org/now
        /opt/csw/bin/pkgutil -y -U
    fi

    python -V | grep "2.7"
    # Install python 2.7
    if [[ "$?" != "0" ]] ; then
        /opt/csw/bin/pkgutil -y -i python27
        ln -sf /opt/csw/bin/python2.7 /usr/bin/python
    fi

    #Install tools
    /opt/csw/bin/pkgutil -y -i git
    /opt/csw/bin/pkgutil -y -i gmake
    /opt/csw/bin/pkgutil -y -i gcc5core
}

compute_version_revision()
{
    wazuh_version=$(cat ${SOURCE}/src/VERSION | cut -d "-" -f1 | cut -c 2-)
    revision="$(cat ${SOURCE}/src/REVISION)"

    echo $wazuh_version > /tmp/VERSION
    echo $revision > /tmp/REVISION

    return 0
}

download_source() {

    cd ${current_path}
    git clone $REPOSITORY $SOURCE

    if [[ "${wazuh_branch}" != "trunk" ]] || [[ "${wazuh_branch}" != "master" ]]; then
        cd $SOURCE
        git checkout $wazuh_branch
    fi
    cd ${current_path}
    compute_version_revision
}

check_version(){
    number_version=`echo "$VERSION" | cut -d v -f 2`
    major_version=`echo ${number_version} | cut -d . -f 1`
    minor_version=`echo ${number_version} | cut -d . -f 2`
    if [ "${major_version}" -eq "3" ]; then
        if [ "${minor_version}" -ge "5" ]; then
            deps_version="true"
        fi
    elif [ "${major_version}" -gt "3" ]; then
        deps_version="true"
    fi
}

#Compile and install wazuh-agent
compile() {

    if [ "${arch}" = "sparc" ]; then
        mv $SOURCE/src/Makefile $SOURCE/src/Makefile.tmp
        sed -n '/OSSEC_LDFLAGS+=-z relax=secadj/!p' $SOURCE/src/Makefile.tmp > $SOURCE/src/Makefile
    fi

    cd ${current_path}
    VERSION=`cat $SOURCE/src/VERSION`
    cd $SOURCE/src
    gmake clean
    config
    check_version
    if [ "${deps_version}" = "true" ]; then
        gmake deps
    fi

    arch="$(uname -p)"
    # Build the binaries
    if [ "$arch" = "sparc" ]; then
        gmake -j $THREADS TARGET=agent PREFIX=${install_path} USE_SELINUX=no USE_BIG_ENDIAN=yes DISABLE_SHARED=yes || exit 1
    else
        gmake -j $THREADS TARGET=agent PREFIX=${install_path} USE_SELINUX=no DISABLE_SHARED=yes || exit 1
    fi

    $SOURCE/install.sh || exit 1
}

create_package() {
    cd ${current_path}
    # Set mog file to the new version
    ver=$VERSION
    if [ $(echo $VERSION | grep "v") ]; then
        ver=`echo $VERSION | cut -c 2-`
        sed "s/<VERSION>/$ver/" ${current_path}/wazuh-agent.mog-template > ${current_path}/wazuh-agent.mog-aux
    else
        sed "s/<VERSION>/$VERSION/" ${current_path}/wazuh-agent.mog-template > ${current_path}/wazuh-agent.mog-aux
    fi
    sed "s/<TAG>/$VERSION/" ${current_path}/wazuh-agent.mog-aux > ${current_path}/wazuh-agent.mog

    echo "Building the package wazuh-agent_$VERSION-sol11-${arch}.p5p"

    # Package generation process
    svcbundle -o wazuh-agent.xml -s service-name=application/wazuh-agent -s start-method="${install_path}/bin/ossec-control start" -s stop-method="${install_path}/bin/ossec-control stop"
    pkgsend generate ${install_path} | pkgfmt > wazuh-agent.p5m.1
    python solaris_fix.py -t SPECS/template_agent_${VERSION}.json -p wazuh-agent.p5m.1 # Fix p5m.1 file
    mv wazuh-agent.p5m.1.aux.fixed wazuh-agent.p5m.1

    # Add the preserve=install-only tag to the configuration files
    for file in etc/ossec.conf etc/local_internal_options.conf etc/client.keys; do
        sed "s:file $file.*:& preserve=install-only:"  wazuh-agent.p5m.1 > wazuh-agent.p5m.1.aux_sed
        mv wazuh-agent.p5m.1.aux_sed wazuh-agent.p5m.1
    done
    # Fix the /etc/ossec-init.conf link
    sed "s:target=etc/ossec-init.conf:target=/etc/ossec-init.conf:"  wazuh-agent.p5m.1 > wazuh-agent.p5m.1.aux
    mv wazuh-agent.p5m.1.aux wazuh-agent.p5m.1
    # Add service files
    echo "file wazuh-agent path=etc/init.d/wazuh-agent owner=root group=sys mode=0744" >> wazuh-agent.p5m.1
    echo "file S97wazuh-agent path=etc/rc2.d/S97wazuh-agent owner=root group=sys mode=0744" >> wazuh-agent.p5m.1
    echo "file S97wazuh-agent path=etc/rc3.d/S97wazuh-agent owner=root group=sys mode=0744" >> wazuh-agent.p5m.1
    # Add user and group ossec
    echo "group groupname=ossec" >> wazuh-agent.p5m.1
    echo "user username=ossec group=ossec" >> wazuh-agent.p5m.1
    pkgmogrify -DARCH=`uname -p` wazuh-agent.p5m.1 wazuh-agent.mog | pkgfmt > wazuh-agent.p5m.2
    pkgsend -s http://localhost:9001 publish -d ${install_path} -d /etc/init.d -d /etc/rc2.d -d /etc/rc3.d wazuh-agent.p5m.2 > pack
    package=`cat pack | grep wazuh | cut -c 13-` # This extracts the name of the package generated in the previous step
    rm -f *.p5p
    pkg_name="wazuh-agent_$VERSION-sol11-${arch}.p5p"
    pkgrecv -s http://localhost:9001 -a -d ${pkg_name} $package

    mkdir -p ${target_dir}

    mv -f ${pkg_name} ${target_dir}

    if [ "${compute_checksums}" = "yes" ]; then
        cd ${target_dir} && /opt/csw/gnu/sha512sum "${pkg_name}" > "${checksum_dir}/${pkg_name}.sha512"
    fi
}

config() {
    echo USER_LANGUAGE="en" > $CONFIG
    echo USER_NO_STOP="y" >> $CONFIG
    echo USER_INSTALL_TYPE="agent" >> $CONFIG
    echo USER_DIR=${install_path} >> $CONFIG
    echo USER_DELETE_DIR="y" >> $CONFIG
    echo USER_CLEANINSTALL="y" >> $CONFIG
    echo USER_BINARYINSTALL="y" >> $CONFIG
    echo USER_AGENT_SERVER_IP="MANAGER_IP" >> $CONFIG
    echo USER_ENABLE_SYSCHECK="y" >> $CONFIG
    echo USER_ENABLE_ROOTCHECK="y" >> $CONFIG
    echo USER_ENABLE_OPENSCAP="y" >> $CONFIG
    echo USER_ENABLE_ACTIVE_RESPONSE="y" >> $CONFIG
    echo USER_CA_STORE="n" >> $CONFIG
}

create_repo() {
    zfs create rpool/wazuh
    zfs set mountpoint=/wazuh rpool/wazuh
    pkgrepo create /wazuh
    ls /wazuh
    pkgrepo -s /wazuh set publisher/prefix=wazuh
    svccfg -s application/pkg/server setprop \ pkg/inst_root=/wazuh
    svccfg -s application/pkg/server setprop pkg/port=9001
    svccfg -s application/pkg/server setprop \ pkg/readonly=false
    svcadm enable application/pkg/server
    svcs application/pkg/server
    # RESTART JUST IN CASE
    svcadm restart application/pkg/server
}

uninstall() {
    echo ${current_path}
    ${current_path}/uninstall.sh
    rm -f `find /etc | grep wazuh`
    rm -f /etc/rc3.d/S97wazuh-agent
    rm -f /etc/rc2.d/S97wazuh-agent
}

clean() {
    rm -rf ${SOURCE}
    cd ${current_path}
    uninstall
    pkg unset-publisher wazuh
    zfs destroy rpool/wazuh
    umount /wazuh
    rm -rf /wazuh
    rm -rf $SOURCE/wazuh
    rm -f wazuh-agent.p5m*
    rm -f wazuh-agent.mog
    rm -f wazuh-agent.mog-aux
    rm -f pack
}

ctrl_c() {
    clean 1
}


show_help() {
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -b, --branch <branch>               Select Git branch or tag e.g. $wazuh_branch."
  echo "    -e, --environment                   Install all the packages necessaries to build the pkg package."
  echo "    -s, --store  <pkg_directory>        Directory to store the resulting pkg package. By default, an output folder will be created."
  echo "    -p, --install-path <pkg_home>       Installation path for the package. By default: /var."
  echo "    -c, --checksum                      Compute the SHA512 checksum of the pkg package."
  echo "    -h, --help                          Shows this help."
  echo
  exit $1
}

build_package() {
    download_source
    create_repo
    compile
    create_package
    clean
    exit 0
}

# Main function, processes user input
main() {
  # If the script is called without arguments
  # show the help
  if [[ -z $1 ]] ; then
    show_help 0
  fi

  build_env="no"
  build_pkg="no"

  while [ -n "$1" ]
  do
    case $1 in
        "-b"|"--branch")
            if [ -n "$2" ]
            then
                wazuh_branch="$2"
                build_pkg="yes"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-h"|"--help")
            show_help
            exit 0
        ;;
        "-e"|"--environment" )
            build_environment
            exit 0
        ;;
        "-p"|"--install-path")
            if [ -n "$2" ]
            then
                install_path="$2"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-s"|"--store")
            if [ -n "$2" ]
            then
                target_dir="$2"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-c" | "--checksum")
            if [ -n "$2" ]; then
                checksum_dir="$2"
                compute_checksums="yes"
                shift 2
            else
                compute_checksums="yes"
                shift 1
            fi
        ;;
        *)
          show_help 1
    esac
  done

  if [[ "${build_env}" = "yes" ]]; then
    build_environment || exit 1
  fi

  if [ -z "${checksum_dir}" ]; then
    checksum_dir="${target_dir}"
  fi

  if [[ "${build_pkg}" = "yes" ]]; then
    build_package || exit 1
  fi

  return 0
}

main "$@"