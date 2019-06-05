#!/usr/local/bin/bash

# Wazuh HP-UX Installer (ver 0.2)
# Copyright (C) 2017 Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


WAZUH_MANAGER_ADDRESS="1.2.3.4"
WAZUH_MANAGER_PASSWORD="CHANGEME"

TARFILE="wazuh-agent-3.0.0-0.1.hpux11v3.ia64.tar"
TARFILE_URL="https://s3-us-west-1.amazonaws.com/packages.wazuh.com/hpux/${TARFILE}"

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

cd /tmp

echo "Checking if /tmp/${TARFILE} exists..."
if [ ! -f "${TARFILE}" ]; then

    echo "Downloading..."
    if type curl >/dev/null 2>&1 ; then
        curl -k -L -O ${TARFILE_URL}
    elif type wget >/dev/null 2>&1 ; then
        wget --no-check-certificate -P /tmp/ -O ${TARFILE} ${TARFILE_URL}
    else
        echo "Your system doesn't have curl nor wget"
        echo "You must download this file: ${TARFILE_URL}"
        echo "and place it in /tmp/${TARFILE}"
        exit 1
    fi
fi

echo "Creating ossec user and group..."
useradd ossec
groupadd ossec

echo "Decompress..."
tar -xvf ${TARFILE}

echo "Connecting to manager..."
/var/ossec/bin/agent-auth -m ${WAZUH_MANAGER_ADDRESS} -P ${WAZUH_MANAGER_PASSWORD}

echo "Updating ossec.conf file..."
sed "s/<server-hostname>.*<\/server-hostname>/<server-hostname>${WAZUH_MANAGER_ADDRESS}<\/server-hostname>/" /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.tmp
mv /var/ossec/etc/ossec.conf.tmp /var/ossec/etc/ossec.conf

sed "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.tmp
mv /var/ossec/etc/ossec.conf.tmp /var/ossec/etc/ossec.conf

echo "Starting wazuh-agent..."
/var/ossec/bin/ossec-control start

echo "Done."

