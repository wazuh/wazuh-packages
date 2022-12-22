#!/bin/bash
FILES_OLD="/usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/*"
FILES_NEW="/etc/wazuh-indexer/opensearch-security/*"
declare -A files_old
declare -A files_new

not_equal=false

# Prints associative array of the old files
function print_old() {
for KEY in "${!files_old[@]}"; do
	# Print the KEY value
	echo "Old-Key: $KEY"
	# Print the VALUE attached to that KEY
	echo "Old-Value: ${files_old[$KEY]}"
done
}

# Prints associative array of the new files
function print_new() {
for KEY in "${!files_new[@]}"; do
	# Print the KEY value
	echo "New-Key: $KEY"
	# Print the VALUE attached to that KEY
	echo "New-Value: ${files_new[$KEY]}"
done
}

# Reads the old files and store their checksum in the array
function read_old_files() {
	for f in $FILES_OLD; do
		echo "Processing $f file..."
		echo "# This is a test" >> $f
		checksum=`md5sum $f | cut -d " " -f1`

		basename=`basename $f`
		files_old[$basename]=$checksum
	done
}

# Reads the new files and store their checksum in the array
function read_new_files() {
	for f in $FILES_NEW; do
		echo "Processing $f file..."
		checksum=`md5sum $f | cut -d " " -f1`

		basename=`basename $f`
		files_new[$basename]=$checksum
	done
}

# Compare the arrays, the loop ends if a different checksum is detected
function compare_files() {
	for i in "${!files_old[@]}"; do
		echo "Comparing $i file checksum..."
		if [[ "$files_old[$i]" == "$files_new[$i]" && $not_equal != true ]]; then
			echo "$i - Same checksum"
		else
			echo "$i - Different checksum"
			not_equal=true
		fi
	done
}

echo 'Installing old wazuh-indexer'
apt-get install ./wazuh-indexer_4.3.7-0.40320.20220825_amd64.deb

read_old_files

echo 'Installing new wazuh-indexer'
apt-get install ./wazuh-indexer_4.5.0-1_amd64.deb

read_new_files

print_old
print_new

compare_files

if [ $not_equal == true ]; then
		echo "Error: different checksums detected"
		exit 1
fi
exit 0
