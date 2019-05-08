#!/bin/bash
# Program to build and sign debian packages, and upload those to a public reprepro repository.
# Copyright (c) 2016-2019 Wazuh, Inc <support@wazuh.com>

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
BRANCH_TAG=""
SPLUNK_VERSION=""
READY_TO_RELEASE=""
CONTAINER_NAME="wazuh-splunk-app:latest"
DESTINATION="/tmp/splunk-app/"
REVISION=" "
TMP_DIRECTORY="/tmp/wazuh-splunk-$(( ( RANDOM % 1000000 )  + 1 ))"
REPOSITORY="wazuh-splunk"

# load config data
scriptpath=$( cd $(dirname $0) ; pwd -P )

help() {
    
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8 or v3.8.1-7.2.3"
    echo "    -s, --store <directory>   [Optional] Destination directory by default /tmp/splunk-app"
    echo "    -r, --revision            [Optional] Package revision that append to version e.g. x.x.x-y.y.y-rev"
    echo "    -h, --help                Show this help."
    echo
    exit $1

    exit $1
}

build_package() {

    # Build the Docker image
    docker build -t ${CONTAINER_NAME} ./Docker/
    # Run Docker and build package
    docker run -t --rm -v "${TMP_DIRECTORY}":/pkg -v "${DESTINATION}":/wazuh_splunk_app ${CONTAINER_NAME} ${wazuh_version} ${splunk_version} ${REVISION} || exit 1
    if [ "$?" = "0" ]; then
        delete_sources 0
    else
        delete_sources 1
    fi
    return 0
}

compute_version_revision() {

    wazuh_version=$(cat SplunkAppForWazuh/default/package.conf | grep version -m 1  | cut -d' ' -f 3)
    splunk_version=$(cat SplunkAppForWazuh/default/package.conf | grep version -m 3  | cut -d ' ' -f 3| head -n 3 | tail -1)

    return 0
}

download_source() {

    if git clone https://github.com/wazuh/${REPOSITORY} -b ${BRANCH_TAG} ${TMP_DIRECTORY} --depth=1 --single-branch -q ; then
        cd ${TMP_DIRECTORY}
        compute_version_revision
        cd -
    else
        echo "Error: Source code from ${BRANCH_TAG} could not be downloaded"
        exit 1
    fi

    return 0
}

delete_sources(){

    exit_code=$1
    rm -rf ${TMP_DIRECTORY}
    exit ${exit_code}
}

main() {
    # Reading command line arguments
    while [ -n "$1" ]
        do
            case "$1" in
            "-h"|"--help")
                help 0 
            ;;
            "-b"|"--branch")
                if [ -n "$2" ]; then
                    BRANCH_TAG="$(echo $2 | cut -d'/' -f2)"
                    HAVE_BRANCH=true
                    shift 2
                else
                    help 1 
                fi
                ;;
            "-s"|"--store")
                if [ -n "$2" ]; then
                    if [[ "${2: -1}" != "/" ]]; then
                    DESTINATION="$2/"
                    else
                    DESTINATION="$2"
                    fi
                    HAVE_DESTINATION=true
                    shift 2
                else
                    help 1 
                fi
                ;;
            "-sp"|"--splunk")
                if [ -n "$2" ]; then
                    SPLUNK_VERSION=$2
                    HAVE_VERSION=truei
                    BRANCH_TAG="v${BRANCH_TAG}-${SPLUNK_VERSION}"
                    shift 2
                else
                    help 1 
                fi
                
                ;;
            "-r"|"--revision")
                if [ -n "$2" ]; then
                    REVISION="$2"
                    shift 2
                else
                    help 1 
                fi
                ;;
            *)
                help 1  
            esac             
        done

    if [[ "$HAVE_BRANCH" == true ]] ; then
        if ! download_source ; then
            delete_sources
            exit 1
        fi
        build_package
    else 
        help 1 
    fi
}

main "$@"
