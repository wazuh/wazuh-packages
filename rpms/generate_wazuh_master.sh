#!/bin/bash
# Program to build and sign debian packages, and upload those to a public reprepro repository.
# Copyright (c) 2014 Santiago Bassett <santiago.bassett@gmail.com>
# Copyright (c) 2016 Wazuh, Inc <support@wazuh.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

#
# CONFIGURATION VARIABLES
#
wazuh_version='3.0'
wazuh_version_final='3.0.0'
# Tag
source_file="v${wazuh_version}.zip"
# Branch
# source_file="${wazuh_version}.zip"
release='1'
packages=(wazuh-manager wazuh-agent)

codenames=(centos-6)
architectures=(i386 x86_64)

# Setting up logfile
scriptpath=$( cd $(dirname $0) ; pwd -P )
logfile=$scriptpath/wazuh_packages.log


szBaseDir=$( pwd -P )
szRpmBaseDir=/home/centos/rpmbuild
szRpmBuildDir=$szRpmBaseDir/SRPMS
szYumRepoDir=$szBaseDir/3.x/yum

# GPG key
signing_key='*********'
signing_pass='*********'

#
# Function to write to LOG_FILE
#
write_log()
{
  if [ ! -e "$logfile" ] ; then
    touch "$logfile"
  fi
  while read text
  do
      local logtime=`date "+%Y-%m-%d %H:%M:%S"`
      echo $logtime": $text" | tee -a $logfile;
  done
}

#
# Check if element is in an array
# Arguments: element array
#
contains_element() {
  local e
  for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 0; done
  return 1
}

#
# Show help function
#
show_help()
{
  echo "
  This tool can be used to generate WAZUH packages for RPM.

  CONFIGURATION: The script is currently configured with the following variables:
    * Packages: ${packages[*]}.
    * Distributions: ${codenames[*]}.
    * Architectures: ${architectures[*]}.
    * WAZUH version: ${wazuh_version}.
    * Source file: ${source_file}.
    * Signing key: ${signing_key}.
    * Release: ${release}
  USAGE: Command line arguments available:
    -h | --help     Displays this help.
    -d | --download Downloads source file and prepares source directories.
    -b | --build   Builds rpm packages.
    -a | --all     Download and Build packages.
  "
}

#
# Downloads packages and prepare source directories.
# This is needed before building the packages.
#
download_source()
{

  # Downloading file
  if wget -O $scriptpath/${source_file} -U ossec https://github.com/wazuh/wazuh/archive/${source_file} ; then
    echo "Successfully downloaded source file ${source_file} from GitHub" | write_log
  else
    echo "Error: File ${source_file} was could not be downloaded" | write_log
    exit 1
  fi

  # Uncompressing files
  tmp_directory=$(echo ${source_file} | sed -e 's/.zip$//')
  if [ -d ${scriptpath}/${tmp_directory} ]; then
    echo " + Deleting previous directory ${scriptpath}/${tmp_directory}" | write_log
    sudo rm -rf ${scriptpath}/${tmp_directory}
    echo "rm -rf ${scriptpath}/${tmp_directory}"
    sleep 10
  fi
  unzip ${scriptpath}/${source_file}
  tmp_directory="wazuh-$wazuh_version"
  if [ ! -d ${scriptpath}/${tmp_directory} ]; then
    # Try to remove leading v
    if [ ${wazuh_version:0:1} = "v" ]
    then
        tmp_directory="wazuh-${wazuh_version:1}"

        if [ ! -d ${scriptpath}/${tmp_directory} ]
        then
          echo "Error: Couldn't find uncompressed directory, named ${tmp_directory}" | write_log
          exit 1
        fi
    else
      echo "Error: Couldn't find uncompressed directory, named ${tmp_directory}" | write_log
      exit 1
    fi
  fi

  # Organizing directories structure
  for package in ${packages[*]}
  do
    echo ${scriptpath}/rpmbuild/SOURCES/$package-$wazuh_version".tar.gz"
    if [ -f ${scriptpath}/rpmbuild/SOURCES/$package-$wazuh_version".tar.gz" ]; then
      echo " + Deleting previous source directory ${scriptpath}/RMPBUILD/SOURCES/$package-$wazuh_version".tar.gz"" | write_log
      sudo rm -rf ${scriptpath}/rpmbuild/SOURCES/$package-$wazuh_version".tar.gz"
    fi
  cp -rp ${scriptpath}/${tmp_directory} ${scriptpath}/$package-$wazuh_version_final
  cd ${scriptpath}
  tar czvf ${scriptpath}/rpmbuild/SOURCES/$package-$wazuh_version_final".tar.gz" $package-$wazuh_version_final/*
  cd ..
  rm -rf $scriptpath/$package-$wazuh_version
  done
  rm -rf $scriptpath/${source_file}
  rm -rf $scriptpath/${tmp_directory}

  echo "The packages directories for ${packages[*]} version ${wazuh_version} have been successfully prepared." | write_log

# Create SRCM packages

  for package in ${packages[*]}
  do
     if rpmbuild -ba ${scriptpath}/rpmbuild/SPECS/$package-$wazuh_version_final.spec ; then
        echo " + Successfully built SRCM package $package-$wazuh_version" | write_log
      else
        echo "aaError: Could not build package $package-$wazuh_version" | write_log
        exit 1
      fi
  done
}

#
# Build packages
#
build_packages()
{
    for package in ${packages[@]}
    do
        for codename in ${codenames[@]}
        do
            for arch in ${architectures[@]}
            do
                if [[ $codename == 'centos-7' && $arch == 'i386' ]] || [[ $codename == 'epel-7' && $arch == 'i386' ]]; then
                    echo "+ $release doesn't have i386" | write_log
                else
                if mock -r $codename-$arch rebuild $szRpmBuildDir/$package-$wazuh_version_final-$release".src.rpm" --resultdir=$szYumRepoDir/ ; then
                    echo " + Successfully built package $package-$wazuh_version $codename-$arch-$release" | write_log
                else
                    echo "Error: Could not build package $package-$wazuh_version $codename-$arch-$release" | write_log
                    exit 1
                fi
                find $szYumRepoDir -name *.log -exec rm  {} \;
                find $szYumRepoDir -name *debuginfo* -exec rm  {} \;
                find $szYumRepoDir -name *src* -exec rm  {} \;
                fi
            done
            sudo rm -rf /var/cache/mock/*
        done
    done

    # SIGN YOUR RPMs HERE
    # Create repo metadata
    createrepo --deltas $szYumRepoDir
}


if [ $# -eq 0 ]; then
  show_help
  exit 0
fi

# Reading command line arguments
while [[ $# > 0 ]]
do
key="$1"
shift

case $key in
  -h|--help)
    show_help
    exit 0
    ;;
  -u|--update)
    update_chroots
    shift
    ;;
  -d|--download)
    download_source
    shift
    ;;
  -b|--build)
    build_packages
    shift
    ;;
  -a|--all)
    download_source
    build_packages
    shift
    ;;
  *)
    echo "Unknown command line argument."
    show_help
    exit 0
    ;;
  esac
done

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2
