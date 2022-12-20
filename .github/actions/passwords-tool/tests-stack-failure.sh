#!/bin/bash

apiPass="$(cat wazuh-install-files/wazuh-passwords.txt | awk "/username: 'wazuh'/{getline;print;}" | awk '{ print $2 }' | tr -d \' )"
adminPass="$(cat wazuh-install-files/wazuh-passwords.txt | awk "/username: 'admin'/{getline;print;}" | awk '{ print $2 }' | tr -d \')"

if ! bash wazuh-passwords-tool.sh -u wazuuuh | grep "ERROR"; then
   exit 1
elif ! sudo bash wazuh-passwords-tool.sh -u admin -p password | grep "ERROR"; then
   exit 1 
elif ! sudo bash wazuh-passwords-tool.sh -au wazuh -ap "${adminPass}" -u wazuh -p password -A | grep "ERROR"; then
   exit 1
elif ! curl -s -u wazuh:wazuh -k -X POST "https://localhost:55000/security/user/authenticate" | grep "Invalid credentials"; then
   exit 1
elif ! curl -s -u wazuuh:"${apiPass}" -k -X POST "https://localhost:55000/security/user/authenticate" | grep "Invalid credentials"; then
   exit 1
elif ! curl -s -XGET https://localhost:9200/ -u admin:admin -k | grep "Unauthorized"; then
   exit 1
elif ! curl -s -XGET https://localhost:9200/ -u adminnnn:"${adminPass}" -k | grep "Unauthorized"; then
   exit 1
fi
