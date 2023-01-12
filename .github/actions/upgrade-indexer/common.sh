#!/bin/bash
FILES_OLD="/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig"
FILES_NEW="/etc/wazuh-indexer/opensearch-security"
declare -A files_old
declare -A files_new
PACKAGE_NAME="${1}"
MAJOR_MINOR_RELEASE=$((${2}))
REFERENCE_VERSION=43

# Check the system to differ between DEB and RPM
function check_system() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="rpm"
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="deb"
    else
        echo "Error: could not detect the system."
        exit 1
    fi

}

# Checks the version of Wazuh with 4.3 version, where path is different.
function check_version() {

    if [ -z "${MAJOR_MINOR_RELEASE}" ]; then
        echo "Error: second argument expected."
        exit 1
    fi

    if [ -z "${REFERENCE_VERSION}" ]; then
        echo "Error: REFERENCE_VERSION is empty."
        exit 1
    fi

    if [ "${MAJOR_MINOR_RELEASE}" -gt "${REFERENCE_VERSION}" ]; then
        FILES_OLD="${FILES_NEW}"
        echo "New path detected (/etc)."
    else
        echo "Old path detected (/usr/share)."
    fi

}

# Compare the arrays, the loop ends if a different checksum is detected
function compare_arrays() {

    for i in "${!files_old[@]}"; do
        echo "Comparing $i file checksum..."
        echo "Old: ${files_old[$i]}"
        echo "New: ${files_new[$i]}"
        if [[ "${files_old[$i]}" == "${files_new[$i]}" ]]; then
            echo "${i} - Same checksum."
        else
            echo "${i} - Different checksum."
            return 1
        fi
    done
    return 0

}

# Steps before installing the RPM release package.
function add_production_repository() {

    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

}

# Reads the files passed by param and store their checksum in the array
function read_files() {

    if [ ! -d "${1}" ]; then
        echo "Error: the directory does not exist. ${1}."
        exit 1
    fi

    for f in ${1}/*; do
        if [ -f "${f}" ]; then
            echo "Processing ${f} file..."

            # Change only the old files
            if [ "${2}" == "old" ]; then
                echo "# This is a test" >> ${f}
                echo "Changed file."
            fi
            checksum=`md5sum ${f} | cut -d " " -f1`

            basename=`basename ${f}`
            if [ "${2}" == "old" ]; then
                files_old["${basename}"]="${checksum}"
            elif [ "${2}" == "new" ]; then
                files_new["${basename}"]="${checksum}"
            fi
        fi
    done

}

# Prints associative array of the files passed by params
function print_files() {

    aux=$(declare -p "$1")
    eval "declare -A arr="${aux#*=}

    if [ "${#arr[@]}" -eq 0 ]; then
        echo "Error: the array didn't scan correctly."
        exit 1
    fi

    for KEY in "${!arr[@]}"; do
        echo "Key: ${KEY}"
        echo "Value: ${arr[${KEY}]}"
    done

}
