#!/bin/bash

get_absolute_path
. $ABSOLUTE_PATH/common.sh
check_system

echo "Installing old version of wazuh indexer..."
if [ $sys_type == "deb" ]; then
    apt-get -y install wazuh-indexer
elif [ $sys_type == "rpm" ]; then
    preinstall_indexer_release
    yum -y install wazuh-indexer
else
    echo "Error: No system detected"
    exit 1
fi

read_files "$FILES_OLD" "old"
echo "Old files..."
print_files "old"

echo "Installing new version of wazuh indexer..."
if [ $sys_type == "deb" ]; then
    apt-get install $PACKAGE_NAME
elif [ $sys_type == "rpm" ]; then
    rpm -Uvh --nofiledigest $PACKAGE_NAME
fi

read_files "$FILES_NEW" "new"
echo "New files..."
print_files "new"

compare_arrays
if [ $EQUAL == false ]; then
        echo "Error: different checksums detected"
        exit 1
fi
echo "Same checksums - Test passed correctly"
exit 0