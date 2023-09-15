#!/bin/bash
FILES_OLD="/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig"
FILES_NEW="/etc/wazuh-indexer/opensearch-security"
declare -A files_old
declare -A files_new
PACKAGE_NAME="${1}"
MAJOR_MINOR_RELEASE=$((${2}))

# This list indicates the SHA values changes between versions
CONFIG_YML_EXCEPTIONS=("config.yml" "25c499973687a8fd3eb8b9ceb3da7a68")

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

    # 43 represents the threshold where the path of the securityconfig
    # files changes (major and minor)
    if [ "${MAJOR_MINOR_RELEASE}" -gt "43" ]; then
        FILES_OLD="${FILES_NEW}"
        echo "New path detected (/etc)."
    else
        echo "Old path detected (/usr/share)."
    fi

}

# Compare the arrays, the loop ends if a different checksum is detected
function compare_arrays() {

    for file in "${!files_old[@]}"; do
        echo "Comparing $file file checksum..."
        echo "Old: ${files_old[$file]}"
        echo "New: ${files_new[$file]}"
        expected=false
        for sha in "${!CONFIG_YML_EXCEPTIONS[@]}"; do
            if [[ "${file}" == "${CONFIG_YML_EXCEPTIONS[0]}" && "${files_new[$file]}" == "${CONFIG_YML_EXCEPTIONS[$sha]}" ]]; then
                expected=true
                break
            fi
        done
        if [[ "${files_old[$file]}" == "${files_new[$file]}" ]]; then
            echo "${file} - Same checksum."
        else
            if [[ $expected ]]; then
                echo "${file} - Expected change."
            else
                echo "${file} - Different checksum."
                exit 1
            fi
        fi
    done

}

# Steps before installing the RPM release package.
function add_production_repository() {

    rpm --import https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH
    echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

}

# Reads the files passed by param and store their checksum in the array
function read_files() {

    if [ ! -d "${1}" ]; then
        echo "Error: the directory does not exist. ${1}."
        exit 1
    fi

    for file in ${1}/*; do
        if [ -f "${file}" ]; then
            echo "Processing ${file} file..."

            # Change only the old files
            if [ "${2}" == "old" ]; then
                echo "# Adding a new line to force changed checksum" >> ${f}
                echo "Changed file."
            fi
            checksum=`md5sum ${file} | cut -d " " -f1`
            basename=`basename ${file}`
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
