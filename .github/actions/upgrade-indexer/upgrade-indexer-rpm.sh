#!/bin/bash
FILES_OLD="/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig"
FILES_NEW="/etc/wazuh-indexer/opensearch-security"
declare -A files_old
declare -A files_new
PACKAGE_NAME=$1
WAZUH_VERSION=$(($2))
REFERENCE_VERSION=43

equal=true

# Checks the version of Wazuh with 4.3 version, where path is different.
function check_version() {
    if [ $WAZUH_VERSION -gt $REFERENCE_VERSION ]; then
        # same path
        FILES_OLD=$FILES_NEW
        echo "New path detected (/etc)"
    else
        echo "Old path detected (/usr/share)"
    fi
}

# Compare the arrays, the loop ends if a different checksum is detected
function compare_arrays() {

    for i in "${!files_old[@]}"; do
        echo "Comparing $i file checksum..."
        echo "Old: ${files_old[$i]}"
        echo "New: ${files_new[$i]}"
        if [[ "${files_old[$i]}" == "${files_new[$i]}" ]]; then
            echo "$i - Same checksum"
        else
            echo "$i - Different checksum"
            equal=false
            break
        fi
    done
}

function preinstall_indexer_release() {
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
}

# Reads the files passed by param and store their checksum in the array
function read_files() {

    for f in $1/*; do
        if [ -f $f ]; then
            echo "Processing $f file..."

            # Change only the old files
            if [ $2 == "old" ]; then
                echo "# This is a test" >> $f
                echo "Changed file"
            fi
            checksum=`md5sum $f | cut -d " " -f1`

            basename=`basename $f`
            if [ $2 == "old" ]; then
                files_old["$basename"]=$checksum
            elif [ $2 == "new" ]; then
                files_new["$basename"]=$checksum
            fi
        fi
    done
}

# Prints associative array of the files passed by params
function print_files() {

    if [ $1 == "old" ]; then
        for KEY in "${!files_old[@]}"; do
            # Print the KEY value
            echo "Key: $KEY"
            # Print the VALUE attached to that KEY
            echo "Value: ${files_old[$KEY]}"
        done
    elif [ $1 == "new" ]; then
        for KEY in "${!files_new[@]}"; do
            # Print the KEY value
            echo "Key: $KEY"
            # Print the VALUE attached to that KEY
            echo "Value: ${files_new[$KEY]}"
        done
    fi
}

echo "FILES_OLD VARIABLE: $FILES_OLD"

echo "Checking version..."
check_version
echo "FILES_OLD VARIABLE: $FILES_OLD"

echo "Installing old version of wazuh indexer..."
# preinstall_indexer_release
# yum -y install wazuh-indexer
curl 'https://packages-dev.wazuh.com/staging/yum/wazuh-indexer-4.4.0-1.x86_64.rpm' --output wazuh-indexer-4.4.0-1.x86_64.rpm
rpm -i ./wazuh-indexer-4.4.0-1.x86_64.rpm

read_files "$FILES_OLD" "old"
echo "Old files..."
print_files "old"

echo "Installing new version of wazuh indexer..."
rpm -Uvh --nofiledigest $PACKAGE_NAME
read_files "$FILES_NEW" "new"
echo "New files..."
print_files "new"

compare_arrays

if [ $equal == false ]; then
        echo "Error: different checksums detected"
        exit 1
fi
echo "Same chechsums - Test passed correctly"
exit 0