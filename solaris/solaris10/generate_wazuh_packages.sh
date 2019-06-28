#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# Wazuh Solaris 10 i386 Package builder.


# CONFIGURATION VARIABLES
BRANCH="$(echo "$2" | cut -d "/" -f2)"
PATH=$PATH:/opt/csw/bin:/usr/sfw/bin
VERSION=""
CURRENT_PATH=`pwd`
REPOSITORY="https://github.com/wazuh/wazuh"
ARCH=`uname -a | cut -d " " -f 6`
INSTALL="/var/ossec"
THREADS=4
PROFILE=agent
deps_version="false"
SOURCE=${CURRENT_PATH}/wazuh
CONFIG="$SOURCE/etc/preloaded-vars.conf"


if [ -z "$BRANCH" ]; then
    BRANCH="master"
fi

if [ -z "$ARCH" ]; then
    ARCH="i386"
fi



dependencies(){
    cd ${CURRENT_PATH}

    # Download and install package manager
    if [ ! -f /opt/csw/bin/pkgutil ]; then
        pkgadd -d http://get.opencsw.org/now
    fi

    #Download and install tools
    pkgutil -y -i git
    pkgutil -y -i make
    pkgutil -y -i automake
    pkgutil -y -i gmake
    pkgutil -y -i autoconf
    pkgutil -y -i libtool
    pkgutil -y -i wget
    pkgutil -y -i curl
    pkgutil -y -i gcc5core


    # Download and install perl5.10
    perl_version=`perl -v | cut -d . -f2 -s | head -n1`

    if [[ $perl_version == "10" ]]; then
        echo " Perl 5.10.1 already installed"
    else
        wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz
        gunzip ./perl-5.10.1.tar.gz
        tar xvf perl-5.10.1.tar
        cd perl-5.10.1
        ./Configure -Dcc=gcc -d -s
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
    echo USER_DIR=$INSTALL >> $CONFIG
    echo USER_DELETE_DIR="y" >> $CONFIG
    echo USER_CLEANINSTALL="y" >> $CONFIG
    echo USER_BINARYINSTALL="y" >> $CONFIG
    echo USER_AGENT_SERVER_IP="MANAGER_IP" >> $CONFIG
    echo USER_ENABLE_SYSCHECK="y" >> $CONFIG
    echo USER_ENABLE_ROOTCHECK="y" >> $CONFIG
    echo USER_ENABLE_OPENSCAP="y" >> $CONFIG
    echo USER_ENABLE_ACTIVE_RESPONSE="y" >> $CONFIG
    echo USER_CA_STORE="/path/to/my_cert.pem" >> $CONFIG
    echo USER_DIR=$INSTALL >> $CONFIG
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
    if [ "$arch" == "sparc" ]; then
        gmake -j $THREADS TARGET=agent PREFIX=$INSTALL USE_SELINUX=no USE_BIG_ENDIAN=yes DISABLE_SHARED=yes
    else
        gmake -j $THREADS TARGET=agent PREFIX=$INSTALL USE_SELINUX=no DISABLE_SHARED=yes
    fi

    cd $SOURCE
    ${CURRENT_PATH}/solaris10_patch.sh
    config
    /bin/bash $SOURCE/install.sh
    cd ${CURRENT_PATH}
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

clone(){
    cd ${CURRENT_PATH}
    git clone $REPOSITORY
    cd $SOURCE
    git checkout $BRANCH
    cp ${CURRENT_PATH}/solaris10_patch.sh ${CURRENT_PATH}/wazuh
    compute_version_revision
}

package(){
    cd ${CURRENT_PATH}
    find /var/ossec | awk 'length > 0' > "wazuh-agent_$VERSION.list"
    ver=`echo $VERSION | cut -d'v' -f 2`
    sed "s:VERSION=\".*\":VERSION=\"$ver\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
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
    pkgtrans -s ${CURRENT_PATH} "wazuh-agent_$VERSION-sol10-$ARCH.pkg" wazuh-agent
}

clean(){
    cd ${CURRENT_PATH}
    rm -rf ${CURRENT_PATH}/wazuh*
    rm -f wazuh-agent*
    rm -f /etc/ossec-init.conf
    rm *.new

    ## Stop and remove application
    /var/ossec/bin/ossec-control stop
    rm -r /var/ossec*
    rm /etc/ossec-init.conf

    ## stop and unload dispatcher
    # /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist

    # remove launchdaemons
    rm -f /etc/init.d/wazuh-agent
    rm -f /etc/ossec-init.conf

    rm -f /etc/rc2.d/S97wazuh-agent
    rm -f /etc/rc3.d/S97wazuh-agent

    ## Remove User and Groups
    userdel ossec
    groupdel ossec
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

show_help()
{
  echo "
  USAGE: Command line arguments available:
    -h   | --help               Displays this help.
    -d   | --download           Download source file and prepares source directories.
    -u   | --utils              Download and install all dependencies.
    -b   | --build              Build Solaris 10 packages.
    -c   | --clean              Clean all. Even installation files.
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
    clone
    exit 0
    ;;
  -b|--build)
    build
    exit 0
    ;;
  -u|--utils)
    dependencies
    exit 0
    ;;
  -c|--clean)
    clean
    exit 0
    ;;
  *)
esac

return 0
