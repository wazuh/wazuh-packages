#!/bin/sh
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2
# Wazuh HP-UX Package builder.


BRANCH="$(echo "$2" | cut -d "/" -f2)"
REVISION="$3"
if [[ -z "$REVISION" ]]; then
    REVISION="1"
fi
INSTALL="/var/ossec"
current_path=`pwd`
SOURCE=${current_path}/wazuh-sources
CONFIG="$SOURCE/etc/preloaded-vars.conf"
VERSION=""
echo "Selected branch: $BRANCH"
echo "Selected installation path: $INSTALL"
PATH=$PATH:/usr/local/bin

utils_and_dependencies() {

  # Resizing partitions for Site Ox boxes (used by Wazuh team)
  if grep 'siteox.com' /etc/motd > /dev/null 2>&1; then
    for partition in "/home" "/tmp"; do
      partition_size=$(df -b | grep $partition | awk -F' ' '{print $5}')
      if [[ ${partition_size} -lt "3145728" ]]; then
        echo "Resizing $partition partition to 3GB"
        volume=$(cat /etc/fstab | grep $partition | awk -F' ' '{print $1}')
        lvextend -L 3000 $volume
        fsadm -b 3072000 $partition > /dev/null 2>&1
      fi
    done
  fi

  echo "Installing dependencies."

  #Install dependencies
  swinstall -s $current_path/depothelper-2.10-hppa_32-11.31.depot \*
  /usr/local/bin/depothelper curl
  /usr/local/bin/depothelper unzip
  /usr/local/bin/depothelper gcc
  /usr/local/bin/depothelper make
  /usr/local/bin/depothelper bash
  /usr/local/bin/depothelper gzip
  /usr/local/bin/depothelper automake
  /usr/local/bin/depothelper autoconf
  /usr/local/bin/depothelper libtool
  /usr/local/bin/depothelper coreutils
  /usr/local/bin/depothelper gdb
  /usr/local/bin/depothelper perl-5.10.1
  cp /usr/bin/perl /tmp/perl
  cp /usr/local/bin/perl5.10.1 /usr/bin/perl
}

config() {
  echo USER_LANGUAGE="en" > $CONFIG
  echo USER_NO_STOP="y" >> $CONFIG
  echo USER_INSTALL_TYPE="agent" >> $CONFIG
  echo USER_DIR=$INSTALL >> $CONFIG
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
  echo " Downloading source"
  #Download source
  /usr/local/bin/curl -k -L -O https://github.com/wazuh/wazuh/archive/$BRANCH.zip
  /usr/local/bin/unzip $BRANCH.zip
  mv wazuh-* $SOURCE
  compute_version_revision
}

check_version(){
  VERSION=`cat $SOURCE/src/VERSION`
  number_version=`echo "$VERSION" | cut -d v -f 2`
  major=`echo $number_version | cut -d . -f 1`
  minor=`echo $number_version | cut -d . -f 2`
  if [ "$major" -eq "3" ]; then
    if [ "$minor" -ge "5" ]; then
      deps_version="true"
    fi
  elif [ "$major" -gt "3" ]; then
    deps_version="true"
  fi
}


compile() {
  echo "Compiling code"
  # Compile and install wazuh
  cd $SOURCE/src
  config
  check_version
  if [ "$deps_version" = "true" ]; then
    gmake deps RESOURCES_URL=http://packages.wazuh.com/deps/$major.$minor
  fi

  gmake TARGET=agent USE_SELINUX=no DISABLE_SHARED=yes
  bash $SOURCE/install.sh
  cd $current_path
}

create_package() {
  echo "Creating package"
  #Build package
  VERSION=`cat /tmp/VERSION`
  rm $INSTALL/wodles/oscap/content/*.xml
  tar cvpf /tmp/wazuh-agent-$VERSION-$REVISION-hpux-11v3-ia64.tar $INSTALL /etc/ossec-init.conf /sbin/init.d/wazuh-agent /sbin/rc2.d/S97wazuh-agent /sbin/rc3.d/S97wazuh-agent
}

#Uninstall agent.

clean() {
  $INSTALL/bin/ossec-control stop
  rm -rf $INSTALL
  rm /etc/ossec-init.conf
  find /sbin -name "*wazuh-agent*" -exec rm {} \;
  userdel ossec
  groupdel ossec
}

show_help()
{
  echo "
  This scripts build wazuh package for HPUX.
  USAGE: Command line options available:
    -h, --help       Displays this help.
    -d, --download   Download Wazuh repository.
    -b, --build      Builds HPUX package.
    -u, --utils      Download and install utilities and dependencies.
    -c, --clean-all  Clean sources and generated files.

  USAGE EXAMPLE:
  --------------
    ./generate_wazuh_packages.sh [option] [branch_tag] [revision]
    ./generate_wazuh_packages.sh -d branches/3.3 1
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

return 0
