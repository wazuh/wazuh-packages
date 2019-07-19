#!/bin/bash

# Program to build the Wazuh WPK packages
# Wazuh package generator
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
LINUX_BUILDER="unified_linux_wpk_builder"
LINUX_BUILDER_DOCKERFILE="${CURRENT_PATH}/unified/linux"
WIN_BUILDER="windows_wpk_builder"
WIN_BUILDER_DOCKERFILE="${CURRENT_PATH}/windows"




function build_wpk_windows() {
  local BRANCH="$1"
  local DESTINATION="$2"
  local KEYDIR="$3"
  local CONTAINER_NAME="$4"
  local JOBS="$5"
  local PACKAGE_NAME="$6"
  local OUT_NAME="$7"

  docker run -t --rm -v ${KEYDIR}:/etc/wazuh -v ${DESTINATION}:/var/local/wazuh -v ${PKG_PATH}:/var/pkg\
      ${CONTAINER_NAME} ${BRANCH} ${JOBS} ${OUT_NAME} ${PACKAGE_NAME}

  return $?
}

function build_wpk_linux() {
  local BRANCH="$1"
  local DESTINATION="$2"
  local KEYDIR="$3"
  local CONTAINER_NAME="$4"
  local JOBS="$5"
  local OUT_NAME="$6"

  docker run -t --rm -v ${KEYDIR}:/etc/wazuh -v ${DESTINATION}:/var/local/wazuh \
      ${CONTAINER_NAME} ${BRANCH} ${JOBS} ${OUT_NAME}

  return $?
}



function build_container() {
  local CONTAINER_NAME="$1"
  local DOCKERFILE_PATH="$2"

  cp run.sh wpkpack.py gen_versions.sh ${DOCKERFILE_PATH}
  docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}

  return 0
}



function help() {
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "    -t,   --target-system <target>              [Required] Select target wpk to build [linux/windows]"
  echo "    -b,   --branch <branch>                     [Required] Select Git branch or tag e.g. $BRANCH"
  echo "    -d,   --destination <path>                  [Required] Set the destination path of package."
  echo "    -k,   --key-dir <arch>                      [Required] Set the WPK key path to sign package."
  echo "    -a,   --architecture <arch>                 [Optional] Target architecture of the package [x86_64]."
  echo "    -j,   --jobs <number>                       [Optional] Number of parallel jobs when compiling."
  echo "    -pd,  --package-directory <directory>       [Required for windows] Package name to pack on wpk."
  echo "    -o,   --output <name>                       [Required] Name to the output package."
  echo "    -h,   --help                                Show this help."
  echo
  exit $1
}



function main() {
  local TARGET=""
  local BRANCH=""
  local DESTINATION=""
  local KEYDIR=""
  local ARCHITECTURE="x86_64"
  local JOBS="4"
  local CONTAINER_NAME=""
  local PKG_NAME=""
  local OUT_NAME=""
  local NO_COMPILE=false

  local HAVE_BRANCH=false
  local HAVE_DESTINATION=false
  local HAVE_TARGET=false
  local HAVE_KEYDIR=false
  local HAVE_PKG_NAME=false
  local HAVE_OUT_NAME=false

  while [ -n "$1" ]
  do
      case "$1" in
      "-t"|"--target-system")
          if [[ -n "$2" ]] && [[ "$2" == "linux" || "$2" == "windows" ]]; then
            local TARGET="$2"
            local HAVE_TARGET=true
            shift 2
          else
            echo "ERROR: Missing target system."
            help 1
          fi
          ;;
      "-b"|"--branch")
          if [[ -n "$2" ]]; then
              local BRANCH="$(echo $2 | cut -d'/' -f2)"
              local HAVE_BRANCH=true
              shift 2
          else
              echo "ERROR: Missing branch."
              help 1
          fi
          ;;
      "-d"|"--destination")
          if [[ -n "$2" ]]; then
              if [[ "${2: -1}" != "/" ]]; then
                local DESTINATION="$2/"
                local HAVE_DESTINATION=true
              else
                local DESTINATION="$2"
                local HAVE_DESTINATION=true
              fi
            shift 2
          else
            echo "ERROR: Missing destination directory."
            help 1
          fi
          ;;
      "-k"|"--key-dir")
          if [[ -n "$2" ]]; then
              if [[ "${2: -1}" != "/" ]]; then
                local KEYDIR="$2/"
                local HAVE_KEYDIR=true
              else
                local KEYDIR="$2"
                local HAVE_KEYDIR=true
              fi
            shift 2
          else
            echo "ERROR: Missing key directory."
            help 1
          fi
          ;;
      "-a"|"--architecture")
          if [[ -n "$2" ]]; then
            local ARCHITECTURE="$2"
            shift 2
          else
            echo "ERROR: Missing architecture."
            help 1
          fi
          ;;
      "-j"|"--jobs")
          if [[ -n "$2" ]]; then
            local JOBS="$2"
            shift 2
          else
            echo "ERROR: Missing jobs."
            help 1
          fi
          ;;
      "-pd"|"--package-directory")
          if [ -n "$2" ]
          then
            local HAVE_PKG_NAME=true
            local PKG_NAME="$2"
            local PKG_PATH=`echo ${PKG_NAME}| rev|cut -d'/' -f2-|rev`
            PKG_NAME=`basename ${PKG_NAME}`
            shift 2
          else
            echo "ERROR: Missing package directory"
            help 1
          fi
          ;;
      "-o"|"--output")
          if [ -n "$2" ]
          then
            local HAVE_OUT_NAME=true
            local OUT_NAME="$2"
            shift 2
          else
            echo "ERROR: Missing output name."
            help 1
          fi
          ;;
      "-h"|"--help")
          help 0
          ;;
      *)
          help 1
      esac
  done

  if [[ "$HAVE_TARGET" == true ]] && [[ "$HAVE_BRANCH" == true ]] && [[ "$HAVE_DESTINATION" == true ]] && [[ "$HAVE_KEYDIR" == true ]] && [[ "$HAVE_OUT_NAME" == true ]]; then

      if [[ "${TARGET}" == "windows" ]]; then
        if [[ "${HAVE_PKG_NAME}" == true ]]; then
          build_container ${WIN_BUILDER} ${WIN_BUILDER_DOCKERFILE} || exit 1
          local CONTAINER_NAME="${WIN_BUILDER}"
          build_wpk_windows ${BRANCH} ${DESTINATION} ${KEYDIR} ${CONTAINER_NAME} ${JOBS} ${PKG_NAME} ${OUT_NAME} || exit 1
        else
          echo "ERROR: No msi package name specified for Windows WPK"
          help 1
        fi
      else
        build_container ${LINUX_BUILDER} ${LINUX_BUILDER_DOCKERFILE} || exit 1
        local CONTAINER_NAME="${LINUX_BUILDER}"
        build_wpk_linux ${BRANCH} ${DESTINATION} ${KEYDIR} ${CONTAINER_NAME} ${JOBS} ${OUT_NAME} || exit 1
      fi



  else
    echo "ERROR: Need more parameters"
    help 1
  fi

  return 0
}

main "$@"
