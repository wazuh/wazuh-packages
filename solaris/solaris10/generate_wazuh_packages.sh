#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# Wazuh Solaris 10 i386 Package builder.


# CONFIGURATION VARIABLES
wazuh_branch="$(echo "$2" | cut -d "/" -f2)"
PATH=$PATH:/opt/csw/bin:/usr/sfw/bin
VERSION=""
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
REPOSITORY="https://github.com/wazuh/wazuh"
ARCH=`uname -p`
install_path="/var/ossec"
THREADS=4
PROFILE=agent
deps_version="false"
SOURCE=${CURRENT_PATH}/repository
CONFIG="$SOURCE/etc/preloaded-vars.conf"
target_dir="${CURRENT_PATH}/output"
control_binary=""

trap ctrl_c INT

if [ -z "${wazuh_branch}" ]; then
    wazuh_branch="master"
fi

if [ -z "$ARCH" ]; then
    ARCH="i386"
fi

set_control_binary() {
  if [ -e ${SOURCE}/src/VERSION ]; then
    wazuh_version=`cat ${SOURCE}/src/VERSION`
    number_version=`echo "${wazuh_version}" | cut -d v -f 2`
    major=`echo $number_version | cut -d . -f 1`
    minor=`echo $number_version | cut -d . -f 2`

    if [ "$major" -le "4" ] && [ "$minor" -le "1" ]; then
      control_binary="ossec-control"
    else
      control_binary="wazuh-control"
    fi
  fi
}

build_environment(){
    cd ${CURRENT_PATH}

    # Download and install package manager
    if [ ! -f /opt/csw/bin/pkgutil ]; then
        echo action=nocheck > /tmp/opencsw-response.txt
        pkgadd -a /tmp/opencsw-response.txt -d http://get.opencsw.org/now -n all
    fi

    #Download and install tools
    pkgutil -y -i git
    pkgutil -y -i make
    pkgutil -y -i automake
    pkgutil -y -i autoconf
    pkgutil -y -i libtool
    pkgutil -y -i wget
    pkgutil -y -i curl
    pkgutil -y -i gcc5core
    /opt/csw/bin/curl -OL http://mirror.opencsw.org/opencsw/allpkgs/gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg.gz
    gunzip -f gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg.gz
    pkgadd -d gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg -n all

    curl -sL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz | gtar xz
    cd cmake-3.18.3
    ./bootstrap
    gmake -j$(nproc) && gmake install
    cd .. && rm -rf cmake-3.18.3
    ln -s /usr/local/bin/cmake /usr/bin/cmake

    # Download and install perl5.10
    perl_version=`perl -v | cut -d . -f2 -s | head -n1`

    if [[ $perl_version == "10" ]]; then
        echo " Perl 5.10.1 already installed"
    else
        wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz
        gunzip ./perl-5.10.1.tar.gz
        tar xvf perl-5.10.1.tar
        cd perl-5.10.1
        ./Configure -Dcc=gcc -d -e -s
        gmake clean
        gmake -d -s
        gmake install -d -s
        cd ..

        # Remove old version of perl and replace it with perl5.10.1
        rm /usr/bin/perl
        mv /opt/csw/bin/perl5.10.1 /usr/bin/
        mv /usr/bin/perl5.10.1 /usr/bin/perl

        # Remove perl code
        rm -rf perl-5.10.1*
    fi
}


config(){
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
    echo USER_CA_STORE="/path/to/my_cert.pem" >> $CONFIG
}

check_version(){
    number_version=`echo "$VERSION" | cut -d v -f 2`
    major=`echo $number_version | cut -d . -f 1`
    minor=`echo $number_version | cut -d . -f 2`
    if [ "$major" -eq 3 ]; then
        if [ "$minor" -ge 5 ]; then
            deps_version="true"
        fi
    elif [ "$major" -gt 3 ]; then
        deps_version="true"
    fi
}

installation(){
    cd ${CURRENT_PATH}
    # Removing incompatible flags
    mv $SOURCE/src/Makefile $SOURCE/src/Makefile.tmp
    sed -n '/OSSEC_LDFLAGS+=-z relax=secadj/!p' $SOURCE/src/Makefile.tmp > $SOURCE/src/Makefile
    cd $SOURCE/src
    gmake clean
    check_version
    if [ "$deps_version" = "true" ]; then
        gmake deps
    fi
    arch="$(uname -p)"
    # Build the binaries
    if [ "$arch" = "sparc" ]; then
        gmake -j $THREADS TARGET=agent PREFIX=${install_path} USE_SELINUX=no USE_BIG_ENDIAN=yes DISABLE_SHARED=yes || return 1
    else
        gmake -j $THREADS TARGET=agent PREFIX=${install_path} USE_SELINUX=no DISABLE_SHARED=yes || return 1
    fi

    cd $SOURCE

    # Patch solaris 10 sh files to change the shebang
    for file in $(find . -name "*.sh");do
        sed 's:#!/bin/sh:#!/usr/xpg4/bin/sh:g' $file > $file.new
        mv $file.new $file && chmod +x $file
    done

    config
    /bin/bash $SOURCE/install.sh || return 1
    cd ${CURRENT_PATH}
}

compute_version_revision()
{
    wazuh_version=$(cat ${SOURCE}/src/VERSION | cut -d "-" -f1 | cut -c 2-)
    revision="$(cat ${SOURCE}/src/REVISION)"

    echo $wazuh_version > /tmp/VERSION
    echo $revision > /tmp/REVISION

    return 0
}

clone(){
    cd ${CURRENT_PATH}
    GIT_SSL_NO_VERIFY=true git clone $REPOSITORY ${SOURCE} || return 1
    cd $SOURCE
    git checkout $wazuh_branch
    cp ${CURRENT_PATH}/solaris10_patch.sh ${CURRENT_PATH}/wazuh
    compute_version_revision

    return 0
}

package(){
    cd ${CURRENT_PATH}
    find ${install_path} | awk 'length > 0' > "wazuh-agent_$VERSION.list"
    ver=`echo $VERSION | cut -d'v' -f 2`
    sed  "s:expected_platform=\".*\":expected_platform=\"$ARCH\":g" checkinstall.sh > checkinstall.sh.new && mv checkinstall.sh.new checkinstall.sh
    sed  "s:ARCH=\".*\":ARCH=\"$ARCH\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    sed  "s:ARCH=\".*\":ARCH=\"$ARCH\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    sed  "s:VERSION=\".*\":VERSION=\"$ver\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    echo "i pkginfo=pkginfo" > "wazuh-agent_$VERSION.proto"
    echo "i checkinstall=checkinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i preinstall=preinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i postinstall=postinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i preremove=preremove.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i postremove=postremove.sh" >> "wazuh-agent_$VERSION.proto"
    echo "f none /etc/ossec-init.conf  0640 root ossec" >> "wazuh-agent_$VERSION.proto"
    echo "f none /etc/init.d/wazuh-agent  0755 root root" >> "wazuh-agent_$VERSION.proto"
    echo "s none /etc/rc2.d/S97wazuh-agent=/etc/init.d/wazuh-agent" >> "wazuh-agent_$VERSION.proto"
    echo "s none /etc/rc3.d/S97wazuh-agent=/etc/init.d/wazuh-agent" >> "wazuh-agent_$VERSION.proto"
    cat "wazuh-agent_$VERSION.list" | pkgproto >> "wazuh-agent_$VERSION.proto"

    echo $VERSION
    pkgmk -o -r / -d . -f "wazuh-agent_$VERSION.proto"
    pkg_name="wazuh-agent_$VERSION-sol10-$ARCH.pkg"
    pkgtrans -s ${CURRENT_PATH} "${pkg_name}" wazuh-agent

    mkdir -p ${target_dir}

    mv -f ${pkg_name} ${target_dir}

    if [ "${compute_checksums}" = "yes" ]; then
        cd ${target_dir} && /opt/csw/gnu/sha512sum "${pkg_name}" > "${checksum_dir}/${pkg_name}.sha512"
    fi
}

clean(){
    set_control_binary
    cd ${CURRENT_PATH}
    rm -rf ${SOURCE}
    rm -rf wazuh-agent wazuh *.list *proto
    rm -f *.new

    ## Stop and remove application
    if [ ! -z $control_binary ]; then
        ${install_path}/bin/${control_binary} stop
    fi

    rm -r ${install_path}*
    rm -f /etc/ossec-init.conf

     # remove launchdaemons
    rm -f /etc/init.d/wazuh-agent
    rm -f /etc/rc2.d/S97wazuh-agent
    rm -f /etc/rc3.d/S97wazuh-agent

    ## Remove User and Groups
    userdel ossec
    groupdel ossec
}

ctrl_c() {
    clean 1
}

build(){

    cd ${CURRENT_PATH}

    VERSION=`cat $SOURCE/src/VERSION`
    echo "------------"
    echo "| Building |"
    echo "------------"

    groupadd ossec
    useradd -g ossec ossec
    chmod +x $SOURCE/solaris10_patch.sh
    installation
    package
}


show_help() {
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -b, --branch <branch>               Select Git branch or tag e.g. $wazuh_branch"
  echo "    -e, --environment                   Install all the packages necessaries to build the pkg package"
  echo "    -s, --store  <pkg_directory>        Directory to store the resulting pkg package. By default, an output folder will be created."
  echo "    -p, --install-path <pkg_home>       Installation path for the package. By default: /var"
  echo "    -c, --checksum                      Compute the SHA512 checksum of the pkg package."
  echo "    -h, --help                          Shows this help"
  echo
  exit $1
}

build_package(){
    clone || return 1
    build || return 1

    return 0
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
        "-e"|"-u"|"--environment" )
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
    build_package || clean 1
  fi

  clean 0

  return 0
}

main "$@"
