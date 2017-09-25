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

ossec_version='2.0'
source_file="master.zip"
release='1'
packages=(wazuh-api)

codenames=(centos-6 centos-7 epel-6 epel-7 fedora-22 fedora-23 fedora-24 fedora-25)

architectures=(x86_64)

# Setting up logfile
scriptpath=$( cd $(dirname $0) ; pwd -P )
logfile=$scriptpath/wazuh_api_packages.log

szBaseDir=$(dirname "$0")
szRpmBaseDir=/home/centos/rpmbuild
szRpmBuildDir=$szRpmBaseDir/SRPMS
szYumRepoDir=$(dirname "$0")/yum

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
  This tool can be used to generate OSSEC packages for Ubuntu and Debian.

  CONFIGURATION: The script is currently configured with the following variables:
    * Packages: ${packages[*]}.
    * Distributions: ${codenames[*]}.
    * Architectures: ${architectures[*]}.
    * OSSEC version: ${ossec_version}.
    * Source file: ${source_file}.
    * Signing key: ${signing_key}.

  USAGE: Command line arguments available:
    -h | --help     Displays this help.
    -d | --download Downloads source file and prepares source directories.
    -b | --build    Builds deb packages.
    -sd | --sync_devel Synchronizes with the DEVEL repository.
    -sp | --sync_prod  Synchronizes with the PROD repository   

  "
}

#
# Downloads packages and prepare source directories.
# This is needed before building the packages.
#
download_source()
{

  # Downloading file
  if wget -O $scriptpath/${source_file} -U ossec https://github.com/wazuh/wazuh-api/archive/master.zip; then
    echo "Successfully downloaded source file ${source_file} from ossec.net" | write_log
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
  tmp_directory="wazuh-api-master"
  if [ ! -d ${scriptpath}/${tmp_directory} ]; then
    echo "Error: Couldn't find uncompressed directory, named ${tmp_directory}" | write_log
    exit 1
  fi
  
  # Organizing directories structure
  for package in ${packages[*]}
  do
    echo ${scriptpath}/rpmbuild/SOURCES/$package-$ossec_version".tar.gz"
    if [ -f ${scriptpath}/rpmbuild/SOURCES/$package-$ossec_version".tar.gz" ]; then
      echo " + Deleting previous source directory ${scriptpath}/RMPBUILD/SOURCES/$package-$ossec_version".tar.gz"" | write_log
      sudo rm -rf ${scriptpath}/rpmbuild/SOURCES/$package-$ossec_version".tar.gz"
    fi
  cp -rp ${scriptpath}/${tmp_directory} ${scriptpath}/$package-$ossec_version
  cd ${scriptpath} 
  tar czvf ${scriptpath}/rpmbuild/SOURCES/$package-$ossec_version".tar.gz" $package-$ossec_version/*
  cd ..
  rm -rf $scriptpath/$package-$ossec_version
  done
  rm -rf $scriptpath/master.zip 
  rm -rf $scriptpath/${tmp_directory}

  echo "The packages directories for ${packages[*]} version ${ossec_version} have been successfully prepared." | write_log

# Create SRCM packages

  for package in ${packages[*]}
  do
     if rpmbuild -ba ${scriptpath}/rpmbuild/SPECS/$package-$ossec_version.spec ; then
        echo " + Successfully built SRCM package $package-$ossec_version" | write_log
      else
        echo "Error: Could not build package $package-$ossec_version" | write_log
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
                        echo "+ Epel and Red hat 7 doesnt have i386" | write_log
                else
                  if mock -r $codename-$arch rebuild $szRpmBuildDir/$package-$ossec_version-$release".el7.centos.src.rpm" --resultdir=$szYumRepoDir/"%(dist)s"/"%(target_arch)s"/ ; then
                     echo " + Successfully built package $package-$ossec_version $codename-$arch" | write_log
                  else
                     echo "Error: Could not build package $package-$ossec_version $codename-$arch" | write_log
                     exit 1
                  fi
                  find $szYumRepoDir -name *.log -exec rm  {} \;
                  find $szYumRepoDir -name *debuginfo* -exec rm  {} \;
                  find $szYumRepoDir -name *src* -exec rm  {} \;
                fi
        done
#        sudo rm -rf /var/cache/mock/*
    done
  done

#sign packages
cd $szYumRepoDir

for createrepo in rhel/6Server/i386 rhel/6Server/x86_64 rhel/7Server/x86_64 el/6/i386 el/6/x86_64 el/7/x86_64 fc/22/x86_64 fc/23/i686 fc/23/x86_64 fc/24/i686 fc/24/x86_64 fc/25/i686 fc/25/x86_64; do
        cp ../GPG/rpmmacros-wazuh ../.rpmmacros
        ../sign_rpm_wazuh.sh $createrepo/*.rpm
        createrepo --deltas "$createrepo"
done

}

#update repository
sync_repository_devel()
{
  if s3cmd -P sync ${scriptpath}/yumtest/ s3://packages.wazuh.com/yumtest/ --delete-removed --follow-symlinks ; then
    echo " + Updated DEVEL repository" | write_log
  else
    echo "Error: Could not sync DEVEL repository" | write_log
    exit 1
  fi
}
sync_repository_prod()
{
  if s3cmd -P sync ${scriptpath}/yum/ s3://packages.wazuh.com/yum/ --delete-removed --follow-symlinks ; then
     echo " + Updated PROD repository" | write_log
  else
    echo "Error: Could not sync PROD repository" | write_log
    exit 1
  fi
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
  -sp|--sync_prod)
    sync_repository_prod
    shift
    ;;
  -sd|--sync_devel)
    sync_repository_devel
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
