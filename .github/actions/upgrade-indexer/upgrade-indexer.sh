#!/bin/bash

# Gets the absolute path of the script, used to load the common.sh file
ABSOLUTE_PATH="$( cd $(dirname ${0}) ; pwd -P )"
. ${ABSOLUTE_PATH}/common.sh

check_system
check_version

echo "Installing old version of Wazuh indexer..."
if [ ${sys_type} == "deb" ]; then
    apt-get -y install wazuh-indexer
elif [ ${sys_type} == "rpm" ]; then
    add_production_repository
    yum -y install wazuh-indexer
else
    echo "Error: No system detected."
    exit 1
fi

read_files "${FILES_OLD}" "old"
echo "Old files..."
print_files "files_old"

echo "Installing new version of Wazuh indexer..."
if [ ${sys_type} == "deb" ]; then
    apt-get install $PACKAGE_NAME
elif [ ${sys_type} == "rpm" ]; then
    yum -y localinstall $PACKAGE_NAME
fi

read_files "${FILES_NEW}" "new"
echo "New files..."
print_files "files_new"

compare_arrays
if [ "$?" -eq 0 ]; then
    echo "Same checksums - Test passed correctly."
    exit 0
fi
echo "Error: different checksums detected."
exit 1
