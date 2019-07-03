#!/bin/bash

# Program to build the Wazuh Virtual Machine
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Dependencies: vagrant, virtualbox, ovftool

#
# CONFIGURATION VARIABLES

scriptpath=$(
  cd $(dirname $0)
  pwd -P
)

function help() {

  OPTIONS:
  echo
  echo "  -b, --build            [Required] Build the OVA and OVF."
  echo "  -v, --version          [Required] Version of wazuh to install on VM."
  echo "  -e, --elastic-version  [Required] Elastic version to download inside VM."
  echo "  -r, --repository       [Required] Status of the packages [stable/unstable]"
  echo "  -d, --directory        [Optional] Where will be installed manager. Default /var/ossec"
  echo "  -c, --clean            [Optional] Clean the local machine."
  echo "  -h, --help             [  Util  ] Show this help."
  echo
  exit $1
}

function clean() {
  rm -f ${scriptpath}/*.ova ${scriptpath}/*.ovf ${scriptpath}/*.mf ${scriptpath}/*.vmdk
  vagrant destroy -f
  return 0
}

function build_ova() {
  local WAZUH_VERSION="$1"
  local OVA_VERSION="$2"
  local OVA_VM="wazuh${OVA_VERSION}.ova"
  local OVF_VM="wazuh${OVA_VERSION}.ovf"
  local OVA_FIXED="wazuh${OVA_VERSION}-fixed.ova"
  local OVA_VMDK="wazuh${OVA_VERSION}-disk001.vmdk"
  local ELK_MAJOR=`echo ${ELK_VERSION}|cut -d"." -f1`

  if [ -e "${OVA_VM}" ] || [ -e "${OVA_VM}" ]; then
    echo "ERROR: files ${OVA_VM} and/or ${OVF_VM} already exists. Please remove them with -c option."
    exit 1
  fi

  #Download filebeat.yml and enable geoip

  curl -so Config_files/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}-rc2/extensions/filebeat/7.x/filebeat.yml

  if [ ${ELK_MAJOR} -eq 7 ]; then 
      sed -i "s|#pipeline: geoip|pipeline: geoip|" Config_files/filebeat.yml
  fi
  

  # Vagrant will provision the VM with all the software. (See vagrant file)
  vagrant destroy -f
  vagrant up
  vagrant halt
  VM_EXPORT=$(vboxmanage list vms | grep -i vm_wazuh | cut -d "\"" -f2)

  # OVA creation with all metadata information.
  vboxmanage export ${VM_EXPORT} -o ${OVA_VM} --vsys 0 --product "Wazuh v${WAZUH_VERSION} OVA" --producturl "https://packages.wazuh.com/vm/wazuh${OVA_VERSION}.ova" --vendor "Wazuh, inc <info@wazuh.com>" --vendorurl "https://wazuh.com" --version "$OVA_VERSION" --description "Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring."

  # Cleaning tasks
  vagrant destroy -f
  vboxmanage unregistervm ${VM_EXPORT}

  tar -xvf ${OVA_VM}

  python Ova2Ovf.py -s ${OVA_VM} -d ${OVA_FIXED}

  rm -f ${OVA_VM} ${OVF_VM} ${OVA_VMDK}
  mv ${OVA_FIXED} ${OVA_VM}
}

function check_version() {
  if [ "$3" == "stable" ]; then
    FLAG=$(git ls-remote --tags https://github.com/wazuh/wazuh-kibana-app | grep ${1}-${2})
  elif [ "$3" == "unstable" ]; then
    FLAG=$(curl -Is https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${1}_${2}.zip | grep -i Content-Length)
  else
    echo "Error, repository value must take 'stable' or 'unstable' value."
    exit
  fi
}

function main() {
  local BUILD=false
  local HAVE_VERSION=false
  local HAVE_ELK_VERSION=false

  local WAZUH_VERSION=""
  local ELK_VERSION=""
  local STATUS=""
  export DIRECTORY="/var/ossec"
  while [ -n "$1" ]; do
    case $1 in
    "-h" | "--help")
      help 0
      ;;

    "-b" | "--build")
      local BUILD=true
      shift 1
      ;;

    "-v" | "--version")
      if [ -n "$2" ]; then
        export OVA_WAZUH_VERSION="$2"
        local WAZUH_VERSION="$2"
        local HAVE_VERSION=true
      else
        echo "ERROR Need wazuh version."
        help 1
      fi
      shift 2
      ;;

    "-e" | "--elastic-version")
      if [ -n "$2" ]; then
        export OVA_ELK_VERSION="$2"
        local ELK_VERSION="$2"
        local HAVE_ELK_VERSION=true
      else
        echo "ERROR: Need elastic version."
        help 1
      fi
      shift 2
      ;;

    "-r" | "--repository")
      if [ -n "$2" ]; then
        export STATUS_PACKAGES="$2"
        local STATUS="$2"
        local HAVE_STATUS=true
      else
        echo "ERROR: Need Status of the packages."
        help 1
      fi
      shift 2
      ;;

    "-d" | "--directory")
      if [ -n "$2" ]; then
        export DIRECTORY="$2"
      else
        echo "ERROR: Need directory to build."
        help 1
      fi
      shift 2
      ;;

    "-c" | "--clean")
      clean
      exit 0
      ;;
    *)
      help 1
      ;;
    esac
  done

  if [[ "${BUILD}" == true ]] && [[ "${HAVE_VERSION}" == true ]] && [[ "${HAVE_ELK_VERSION}" == true ]] && [[ "${HAVE_STATUS}" == true ]]; then
    check_version ${WAZUH_VERSION} ${ELK_VERSION} ${STATUS}
    if [ -n "${FLAG}" ]; then
      local OVA_VERSION="${WAZUH_VERSION}_${ELK_VERSION}"
      echo "Version to build: ${WAZUH_VERSION}-${ELK_VERSION} with ${STATUS} repository."
      build_ova ${WAZUH_VERSION} ${OVA_VERSION}
    else
      echo "Error version ${WAZUH_VERSION}-${ELK_VERSION} not supported."
    fi

  else
    echo "ERROR: Need more parameters."
    help 1
  fi

  return 0
}

main "$@"
