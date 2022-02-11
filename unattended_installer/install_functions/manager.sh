# Wazuh installer - manager.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function manager_startCluster() {

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

function manager_install() {

    logger "Starting the Wazuh manager installation."

    if [ "${sys_type}" == "zypper" ]; then
        eval "${sys_type} -n install wazuh-manager=${wazuh_version}-${wazuh_revision} ${debug}"
    elif [ "${sys_type}" == "yum" ]; then
        eval "${sys_type} install wazuh-manager${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "DEBIAN_FRONTEND=noninteractive ${sys_type} install wazuh-manager${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh installation failed."
        wazuhinstalled="manager"
        common_rollBack
        exit 1
    else
        wazuhinstalled="1"
        logger "Wazuh manager installation finished."
    fi
}

function manager_uninstall() {

    logger "Wazuh manager and Filebeat will be uninstalled."

    # Remove Wazuh
    logger -w "Removing Wazuh manager."
    if [[ -n "${wazuhinstalled}" ]];then

        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-manager -y ${debug} &"
            wait
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-manager ${debug} &"
            wait
            eval "rm -f /etc/init.d/wazuh-manager ${debug} &"
            wait
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-manager -y ${debug} &"
            wait
        fi
    fi

    until [ -z "${wazuh_remaining_files}" ]
    do
        eval "rm -rf /var/ossec/ ${debug}"
        checkWazuhRemainingFiles
    done

    # Remove Filebeat
    logger -w "Removing Filebeat."
    if [[ -n "${filebeatinstalled}" ]]; then

        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug} &"
            wait
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug} &"
            wait
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug} &"
            wait
        fi
    fi

    until [ -z "${filebeat_remaining_files}" ]
    do
        elements_to_remove=(    "/var/log/filebeat/"
                                "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                                "/etc/systemd/system/multi-user.target.wants/filebeat.service"
                                "/var/lib/filebeat/"
                                "/usr/share/filebeat/"
                                "/etc/filebeat/"
                            )
        eval "rm -rf ${elements_to_remove[*]} ${debug}"
        checkFilebeatRemainingFiles
    done

}
