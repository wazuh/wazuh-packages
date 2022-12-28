#!/bin/bash
FILES_OLD="/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig"
FILES_NEW="/etc/wazuh-indexer/opensearch-security"
declare -A files_old
declare -A files_new

not_equal=false

# Prints associative array of the files passed by params
function print_files() {
    local -n files=$1

    for KEY in "${!files[@]}"; do
        # Print the KEY value
        echo "Key: $KEY"
        # Print the VALUE attached to that KEY
        echo "Value: ${files[$KEY]}"
    done
}

# Reads the files passed by param and store their checksum in the array
function read_files() {
    local -n files=$2

    for f in $1/*; do
        if [ -f $f ]; then
            echo "Processing $f file..."
            echo "# This is a test" >> $f
            checksum=`md5sum $f | cut -d " " -f1`

            basename=`basename $f`
            files[$basename]=$checksum
        fi
    done
}

# Compare the arrays, the loop ends if a different checksum is detected
function compare_arrays() {
    local -n array_old=$1
    local -n array_new=$2

    for i in "${!array_old[@]}"; do
        echo "Comparing $i file checksum..."
        if [[ "$array_old[$i]" == "$array_new[$i]" && $not_equal != true ]]; then
            echo "$i - Same checksum"
        else
            echo "$i - Different checksum"
            not_equal=true
        fi
    done
}

# apt-get -y install wazuh-indexer
# read_files "$FILES_OLD" files_old
# echo "Old files..."
# print_files files_old
#
# apt-get install ./$PACKAGE_NAME
# read_files "$FILES_NEW" files_new
# echo "New files..."
# print_files files_new

echo "Nombre del paquete:"
echo {$env.PACKAGE_NAME}

# compare_arrays files_old files_new

if [ $not_equal == true ]; then
        echo "Error: different checksums detected"
        exit 1
fi
exit 0
