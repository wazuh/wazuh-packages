#!/bin/ksh

# Script to build Wazuh RPM package for AIX
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -exf

# Script configuration variables
install_path="/var/ossec"
wazuh_branch="master"
target_dir="/tmp/build"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
 echo "This script must be run as root"
 exit 1
fi

# Get AIX major and minor version
aix_version=$(oslevel)
aix_major=$(echo ${aix_version} | cut -d'.' -f 1)
aix_minor=$(echo ${aix_version} | cut -d'.' -f 2)

export PATH=/opt/freeware/bin:$PATH

show_help() {
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -b, --branch <branch>               Select Git branch or tag e.g. $BRANCH"
  echo "    -e, --environment                   Install all the packages necessaries to build the RPM package"
  echo "    -s, --store  <rpm_directory>        Directory to store the resulting RPM package. By default: /tmp/build"
  echo "    -p, --install-path <rpm_home>       Installation path for the package. By default: /var"
  echo "    -h, --help                          Shows this help"
  echo
  exit $1
}

# Function to install perl 5.10 on AIX 5
build_perl() {

  wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz
  gunzip perl-5.10.1.tar.gz && tar -xvf perl-5.10.1.tar
  cd perl-5.10.1 && ./Configure -des -Dcc='gcc'
  make && make install
  ln -fs /usr/local/bin/perl /bin/perl
  ln -fs /usr/local/bin/perl /opt/freeware/bin/perl
  cd .. && rm -rf perl-5.10.1*

  return 0
}

# Function to build the compilation environment
build_environment() {

  rpm="rpm -Uvh --nodeps"

  $rpm http://www.oss4aix.org/download/RPMS/autoconf/autoconf-2.69-2.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/automake/automake-1.16.1-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/bash/bash-4.4-4.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/bzip2/bzip2-1.0.6-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/coreutils/coreutils-64bit-8.28-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/curl/curl-7.57.0-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/expat/expat-2.2.5-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/expat/expat-devel-2.2.5-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/gettext/gettext-0.17-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/glib2/glib2-2.38.2-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/glib/glib-devel-1.2.10-3.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/gmp/gmp-6.1.2-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/gmp/gmp-devel-6.1.2-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/grep/grep-3.1-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/gzip/gzip-1.8-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/info/info-6.4-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libffi/libffi-3.2.1-2.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libiconv/libiconv-1.15-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libidn/libidn-1.33-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libsigsegv/libsigsegv-2.12-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libssh2/libssh2-1.8.0-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/libtool/libtool-2.4.6-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/m4/m4-1.4.18-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/make/make-4.2.1-1.aix5.3.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/openldap/openldap-2.4.44-0.1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/openssl/openssl-1.0.2o-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/pcre/pcre-8.41-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/pkg-config/pkg-config-0.29.1-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/readline/readline-7.0-3.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/sed/sed-4.5-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/wget/wget-1.19.2-1.aix5.1.ppc.rpm || true
  $rpm http://www.oss4aix.org/download/RPMS/zlib/zlib-1.2.11-1.aix5.1.ppc.rpm || true

  if [[ "${aix_major}" = "5" ]]; then
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-4.8.2-1.aix5.3.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-cpp-4.8.2-1.aix5.3.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libgcc-4.8.2-1.aix5.3.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-4.8.2-1.aix5.3.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-devel-4.8.2-1.aix5.3.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/libmpc/libmpc-1.0.2-1.aix5.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/mpfr/mpfr-3.0.0-1.aix5.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "6" ]] || [[ "${aix_major}" = "7" ]]; then
    $rpm http://www.oss4aix.org/download/RPMS/isl/isl-0.18-1.aix5.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/mpfr/mpfr-3.1.6-1.aix5.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/libmpc/libmpc-1.0.3-1.aix5.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/file/file-5.32-1.aix5.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/file/file-libs-5.32-1.aix5.1.ppc.rpm || true
    $rpm http://public.dhe.ibm.com/aix/freeSoftware/aixtoolbox/RPMS/ppc/perl/perl-5.28.0-1.aix6.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "6" ]]; then
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-cpp-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libgcc-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-6.3.0-1.aix6.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-devel-6.3.0-1.aix6.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "7" ]] && [[ "${aix_minor}" = "1" ]]; then
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-cpp-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libgcc-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-6.3.0-1.aix7.1.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-devel-6.3.0-1.aix7.1.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "7" ]] && [[ "${aix_minor}" = "2" ]]; then
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/gcc-cpp-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libgcc-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-6.3.0-1.aix7.2.ppc.rpm || true
    $rpm http://www.oss4aix.org/download/RPMS/gcc/libstdc++-devel-6.3.0-1.aix7.2.ppc.rpm || true
  fi

  if [[ "${aix_major}" = "5" ]]; then
    build_perl
  fi

  return 0
}

build_package() {

  source_code="https://api.github.com/repos/wazuh/wazuh/tarball/${wazuh_branch}"

  rm -f wazuh.tar.gz && wget -O wazuh.tar.gz --no-check-certificate ${source_code}
  rm -rf wazuh-wazuh-* wazuh-agent-*
  extracted_directory=$(gunzip -c wazuh.tar.gz | tar -xvf - | tail -n 1 | cut -d' ' -f2 | cut -d'/' -f1)
  wazuh_version=$(cat ${extracted_directory}/src/VERSION | cut -d'v' -f2)
  cp -pr ${extracted_directory} wazuh-agent-${wazuh_version}

  rpm_build_dir="/opt/freeware/src/packages"
  mkdir -p ${rpm_build_dir}/BUILD
  mkdir -p ${rpm_build_dir}/BUILDROOT
  mkdir -p ${rpm_build_dir}/RPMS
  mkdir -p ${rpm_build_dir}/SOURCES
  mkdir -p ${rpm_build_dir}/SPECS
  mkdir -p ${rpm_build_dir}/SRPMS

  package_name=wazuh-agent-${wazuh_version}
  tar cf ${package_name}.tar ${package_name} && gzip ${package_name}.tar
  mv ${package_name}.tar.gz ${rpm_build_dir}/SOURCES/

  cp SPECS/${wazuh_version}/wazuh-agent-${wazuh_version}-aix.spec ${rpm_build_dir}/SPECS

  if [[ ${aix_major} = "6" ]] && [[ -f /opt/freeware/lib/gcc/powerpc-ibm-aix6.1.1.0/6.3.0/include-fixed/sys/socket.h ]]; then
    ignored_lib=/opt/freeware/lib/gcc/powerpc-ibm-aix6.1.1.0/6.3.0/include-fixed/sys/socket.h
    mv ${ignored_lib} ${ignored_lib}.backup
  fi

  package_release="1"
  directory_base="/var"
  init_scripts="/etc/rc.d/init.d"
  sysconfdir="/etc"

  rpm --define "_topdir ${rpm_build_dir}" --define "_localstatedir ${directory_base}" \
  --define "_init_scripts ${init_scripts}" --define "_sysconfdir ${sysconfdir}" \
  -bb ${rpm_build_dir}/SPECS/${package_name}-aix.spec

  if [[ ${aix_major} = "6" ]]; then
    mv ${ignored_lib}.backup ${ignored_lib}
  fi

  # If they exist, remove the installed files in ${directory_base}
  rm -rf ${directory_base}/ossec /etc/ossec-init.conf
  find /etc/ -name "*wazuh*" -exec rm {} \;

  if [ ! -d ${target_dir} ]; then
    mkdir -p ${target_dir}
  fi

  rpm_file=${package_name}-${package_release}.aix${aix_major}.${aix_minor}.ppc.rpm
  mv ${rpm_build_dir}/RPMS/ppc/${rpm_file} ${target_dir}

  if [ -f ${target_dir}/${rpm_file} ]; then
    echo "Your package ${rpm_file} is stored in ${target_dir}"
  else
    echo "Error: RPM package could not be created"
    exit 1
  fi

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
  build_rpm="no"

  while [ -n "$1" ]
  do
    case $1 in
        "-b"|"--branch")
          if [ -n "$2" ]
          then
              wazuh_branch="$2"
              build_rpm="yes"
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
        *)
          show_help 1
    esac
  done

  if [[ "${build_env}" = "yes" ]]; then
    build_environment || exit 1
  fi

  if [[ "${build_rpm}" = "yes" ]]; then
    build_package || exit 1
  fi

  return 0
}

main "$@"
