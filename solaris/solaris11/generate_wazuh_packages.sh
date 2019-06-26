#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# Wazuh Solaris 11 Package builder.

REPOSITORY="https://github.com/wazuh/wazuh"
BRANCH="$(echo "$2" | cut -d "/" -f2)"
INSTALL="/var/ossec"
THREADS="6"
PROFILE="agent"
PATH=$PATH:/opt/csw/bin/
current_path=`pwd`
arch=`uname -p`
SOURCE=${current_path}/wazuh
CONFIG="$SOURCE/etc/preloaded-vars.conf"
VERSION=""

utils_and_dependencies() {
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

    if [ "${READY_TO_RELEASE}" == "yes" ]; then
        revision="${OPTIONAL_REVISION}"
    else
        revision="0.${revision}dev"
    fi

    echo $wazuh_version > /tmp/VERSION
    echo $revision > /tmp/REVISION

    return 0
}

download_source() {

    cd ${current_path}
    git clone $REPOSITORY

    if [[ "${BRANCH}" != "trunk" ]] || [[ "${BRANCH}" != "master" ]]; then
        cd $SOURCE
        git checkout $BRANCH
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
    if [ "$arch" == "sparc" ]; then
        gmake -j $THREADS TARGET=agent PREFIX=$INSTALL USE_SELINUX=no USE_BIG_ENDIAN=yes
    else
        gmake -j $THREADS TARGET=agent PREFIX=$INSTALL USE_SELINUX=no
    fi
    gmake -j $THREADS TARGET=$PROFILE
    $SOURCE/install.sh
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
    svcbundle -o wazuh-agent.xml -s service-name=application/wazuh-agent -s start-method="/var/ossec/bin/ossec-control start" -s stop-method="/var/ossec/bin/ossec-control stop"
    pkgsend generate /var/ossec | pkgfmt > wazuh-agent.p5m.1
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
    pkgdepend generate -md /var/ossec -d /etc/init.d -d /etc/rc2.d -d /etc/rc3.d wazuh-agent.p5m.2 > wazuh-agent.p5m.3
    pkgdepend resolve -m wazuh-agent.p5m.3
    pkgsend -s http://localhost:9001 publish -d /var/ossec -d /etc/init.d -d /etc/rc2.d -d /etc/rc3.d wazuh-agent.p5m.3.res > pack
    package=`cat pack | grep wazuh | cut -c 13-` # This extracts the name of the package generated in the previous step
    rm -f *.p5p
    pkgrecv -s http://localhost:9001 -a -d wazuh-agent_$VERSION-sol11-${arch}.p5p $package
}

config() {
    echo USER_LANGUAGE="en" > $CONFIG
    echo USER_NO_STOP="y" >> $CONFIG
    echo USER_INSTALL_TYPE="agent" >> $CONFIG
    echo USER_DIR=/var/ossec >> $CONFIG
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
    rm -f ${current_path}/wazuh-agent_$VERSION-sol11-${arch}.p5p
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


show_help()
{
  echo "
  This scripts build wazuh package for Solaris 11 Intel based architecture.
  USAGE: Command line options available:
    -h, --help         Displays this help.
    -d, --download     Download Wazuh repository.
    -b, --build        Builds Solaris11 packages.
    -u, --utils        Download and install utilities and dependencies.
    -c, --clean-all    Clean sources, local respository and generated files.
  "
}

# Reading command line arguments
key="$1"
case $key in
  -h|--help)
    show_help
    exit 0
    ;;
  -d|--download)
    download_source
    exit 0
    ;;
  -b|--build)
    create_repo
    compile
    create_package
    exit 0
    ;;
    -u|--utils)
    utils_and_dependencies
    exit 0
    ;;
    -c|--clean-all)
    clean
    exit 0
    ;;
  *)
esac

exit 0
