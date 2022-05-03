#!/bin/sh

# Configure JVM options for Wazuh indexer
ram_mb=$(free -m | awk '/^Mem:/{print $2}')
ram="$(( ram_mb / 2 ))"

if [ "${ram}" -eq "0" ]; then
    ram=1024;
fi
eval "sed -i "s/-Xms1g/-Xms${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"
eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"