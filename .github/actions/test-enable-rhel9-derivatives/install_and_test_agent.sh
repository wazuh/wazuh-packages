#!/bin/bash

echo "Installing Wazuh Agent."
yum install -y "/packages/$1"

echo "Enabling Wazuh Agent."
systemctl enable wazuh-agent
if [ "$?" -eq 0 ]; then
    echo "Wazuh agent enabled - Test passed correctly."
    exit 0
else 
    echo "Error: Wazuh agent not enabled."
    exit 1
fi