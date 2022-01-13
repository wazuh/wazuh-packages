# Wazuh installer - wazuh.sh library. 
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function configureWazuhCluster() {

    for i in "${!wazuh_servers_node_names[@]}"; do
        if [[ "${wazuh_servers_node_names[i]}" == "${winame}" ]]; then
            pos="${i}";
        fi
    done

    for i in "${!wazuh_servers_node_types[@]}"; do
        if [[ "${wazuh_servers_node_types[i],,}" == "master" ]]; then
            master_address=${wazuh_servers_node_ips[i]}
        fi
    done

    key=$(tar -axf "${tar_file}" ./clusterkey -O)
    bind_address="0.0.0.0"
    port="1516"
    hidden="no"
    disabled="no"
    lstart=$(grep -n "<cluster>" /var/ossec/etc/ossec.conf | cut -d : -f 1)
    lend=$(grep -n "</cluster>" /var/ossec/etc/ossec.conf | cut -d : -f 1)

    eval 'sed -i -e "${lstart},${lend}s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/" \
        -e "${lstart},${lend}s/<node_name>.*<\/node_name>/<node_name>${winame}<\/node_name>/" \
        -e "${lstart},${lend}s/<node_type>.*<\/node_type>/<node_type>${wazuh_servers_node_types[pos],,}<\/node_type>/" \
        -e "${lstart},${lend}s/<key>.*<\/key>/<key>${key}<\/key>/" \
        -e "${lstart},${lend}s/<port>.*<\/port>/<port>${port}<\/port>/" \
        -e "${lstart},${lend}s/<bind_addr>.*<\/bind_addr>/<bind_addr>${bind_address}<\/bind_addr>/" \
        -e "${lstart},${lend}s/<node>.*<\/node>/<node>${master_address}<\/node>/" \
        -e "${lstart},${lend}s/<hidden>.*<\/hidden>/<hidden>${hidden}<\/hidden>/" \
        -e "${lstart},${lend}s/<disabled>.*<\/disabled>/<disabled>${disabled}<\/disabled>/" \
        /var/ossec/etc/ossec.conf'

}

function installWazuh() {

    logger "Starting the Wazuh manager installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "${sys_type} -n install wazuh-manager=${wazuh_version}-${wazuh_revision} ${debug}"
    else
        eval "${sys_type} install wazuh-manager${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh installation failed"
        rollBack
        exit 1
    else
        wazuhinstalled="1"
        logger "Wazuh manager installation finished."
    fi   
}
