#!/bin/sh
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2
# Wazuh HP-UX Package builder.


install_path="/var/ossec"
current_path=`pwd`
source_directory=${current_path}/wazuh-sources
configuration_file="${source_directory}/etc/preloaded-vars.conf"
PATH=$PATH:/usr/local/bin
target_dir="${current_path}/output"
checksum_dir=""
wazuh_version=""
wazuh_revision="1"

build_environment() {

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
  /usr/local/bin/depothelper -f curl
  /usr/local/bin/depothelper -f unzip
  /usr/local/bin/depothelper -f gcc
  /usr/local/bin/depothelper -f make
  /usr/local/bin/depothelper -f bash
  /usr/local/bin/depothelper -f gzip
  /usr/local/bin/depothelper -f automake
  /usr/local/bin/depothelper -f autoconf
  /usr/local/bin/depothelper -f libtool
  /usr/local/bin/depothelper -f coreutils
  /usr/local/bin/depothelper -f gdb
  /usr/local/bin/depothelper -f perl-5.10.1
  cp /usr/bin/perl /tmp/perl
  cp /usr/local/bin/perl5.10.1 /usr/bin/perl
}

config() {
  echo USER_LANGUAGE="en" > ${configuration_file}
  echo USER_NO_STOP="y" >> ${configuration_file}
  echo USER_INSTALL_TYPE="agent" >> ${configuration_file}
  echo USER_DIR=${install_path} >> ${configuration_file}
  echo USER_DELETE_DIR="y" >> ${configuration_file}
  echo USER_CLEANINSTALL="y" >> ${configuration_file}
  echo USER_BINARYINSTALL="y" >> ${configuration_file}
  echo USER_AGENT_SERVER_IP="MANAGER_IP" >> ${configuration_file}
  echo USER_ENABLE_SYSCHECK="y" >> ${configuration_file}
  echo USER_ENABLE_ROOTCHECK="y" >> ${configuration_file}
  echo USER_ENABLE_OPENSCAP="y" >> ${configuration_file}
  echo USER_ENABLE_ACTIVE_RESPONSE="y" >> ${configuration_file}
  echo USER_CA_STORE="n" >> ${configuration_file}
}

compute_version_revision()
{
  wazuh_version=$(cat ${source_directory}/src/VERSION | cut -d "-" -f1 | cut -c 2-)

  echo ${wazuh_version} > /tmp/VERSION
  echo ${wazuh_revision} > /tmp/REVISION

  return 0
}

download_source() {
  echo " Downloading source"
  /usr/local/bin/curl -k -L -O https://github.com/wazuh/wazuh/archive/${wazuh_branch}.zip
  /usr/local/bin/unzip ${wazuh_branch}.zip
  mv wazuh-* ${source_directory}
  compute_version_revision
}

check_version(){
  wazuh_version=`cat ${source_directory}/src/VERSION`
  number_version=`echo "${wazuh_version}" | cut -d v -f 2`
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
  cd ${source_directory}/src
  config
  check_version
  if [ "$deps_version" = "true" ]; then
    gmake deps RESOURCES_URL=http://packages.wazuh.com/deps/$major.$minor
  fi

  gmake TARGET=agent USE_SELINUX=no DISABLE_SHARED=yes
  bash ${source_directory}/install.sh
  cd $current_path
}

create_package() {
  echo "Creating package"

  if [ ! -d ${target_dir} ]; then
    mkdir -p ${target_dir}
  fi

  #Build package
  VERSION=`cat /tmp/VERSION`
  rm ${install_path}/wodles/oscap/content/*.xml
  wazuh_version=`echo "${wazuh_version}" | cut -d v -f 2`
  pkg_name="wazuh-agent-${wazuh_version}-${wazuh_revision}-hpux-11v3-ia64.tar"
  tar cvpf ${target_dir}/${pkg_name} ${install_path} /etc/ossec-init.conf /sbin/init.d/wazuh-agent /sbin/rc2.d/S97wazuh-agent /sbin/rc3.d/S97wazuh-agent

  if [ "${compute_checksums}" = "yes" ]; then
    cd ${target_dir}
    pkg_checksum="$(openssl dgst -sha512 ${pkg_name})"
    echo "${pkg_checksum}  ${pkg_name}" > ${checksum_dir}/${pkg_name}.sha512
  fi
}

#Uninstall agent.

clean() {
  exit_code=$1
  ${install_path}/bin/ossec-control stop
  rm -rf ${install_path}
  rm /etc/ossec-init.conf
  find /sbin -name "*wazuh-agent*" -exec rm {} \;
  userdel ossec
  groupdel ossec

  exit ${exit_code}
}

show_help() {
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -e Install all the packages necessaries to build the TAR package"
  echo "    -b <branch> Select Git branch. Example v3.5.0"
  echo "    -s <tar_directory> Directory to store the resulting tar package. By default, an output folder will be created."
  echo "    -p <tar_home> Installation path for the package. By default: /var"
  echo "    -c, --checksum Compute the SHA512 checksum of the TAR package."
  echo "    -h Shows this help"
  echo
  exit $1
}

build_package() {
  download_source
  compile
  create_package
  clean 0
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
      "-b")
        if [ -n "$2" ]
        then
          wazuh_branch="$2"
          build_pkg="yes"
          shift 2
        else
          show_help 1
        fi
      ;;
      "-h")
        show_help
        exit 0
      ;;
      "-e")
        build_environment
        exit 0
      ;;
      "-p")
        if [ -n "$2" ]
        then
          install_path="$2"
          shift 2
        else
          show_help 1
        fi
      ;;
      "-s")
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

  return 0
}

main "$@"