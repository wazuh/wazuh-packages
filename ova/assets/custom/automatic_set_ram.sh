#!/bin/sh

# Configure JVM options for Wazuh indexer
ram_mb=$(free -m | awk '/^Mem:/{print $2}')
ram="$(( ram_mb / 2 ))"

if [ "${ram}" -eq "0" ]; then
    ram=1024;
fi

regex="^\-Xmx\K[0-9]+"
file="/etc/wazuh-indexer/jvm.options"
value=$(grep -oP ${regex} ${file})

if [[ "${value}" != "${ram}" ]]; then
    eval "sed -i "s/^-Xms.*$/-Xms${ram}m/" ${file} ${debug}"
    eval "sed -i "s/^-Xmx.*$/-Xmx${ram}m/" ${file} ${debug}"
fi

systemctl stop updateIndexerHeap.service