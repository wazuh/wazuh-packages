# Wazuh installer - dashboard.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly d_certs_path="/etc/wazuh-dashboard/certs/"

function dashboard_configure() {

    dashboard_copyCertificates

    if [ -n "${AIO}" ]; then
        eval "common_getConfig dashboard/dashboard_unattended.yml /etc/wazuh-dashboard/dashboard.yml ${debug}"
    else
        eval "common_getConfig dashboard/dashboard_unattended_distributed.yml /etc/wazuh-dashboard/dashboard.yml ${debug}"
        if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
            pos=0
            ip=${dashboard_node_ips[0]}
        else
            for i in "${!dashboard_node_names[@]}"; do
                if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                    pos="${i}";
                fi
            done
            ip=${dashboard_node_ips[pos]}
        fi

        echo 'server.host: "'${ip}'"' >> /etc/wazuh-dashboard/dashboard.yml

        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            echo "opensearch.hosts: https://"${indexer_node_ips[0]}":9700" >> /etc/wazuh-dashboard/dashboard.yml
        else
            echo "opensearch.hosts:" >> /etc/wazuh-dashboard/dashboard.yml
            for i in "${indexer_node_ips[@]}"; do
                    echo "  - https://${i}:9700" >> /etc/wazuh-dashboard/dashboard.yml
            done
        fi
    fi

    logger "Wazuh dashboard post-install configuration finished."

}

function dashboard_copyCertificates() {

    eval "rm -f ${d_certs_path}/* ${debug}"
    if [ -f "${tar_file}" ]; then

        name=${dashboard_node_names[pos]}

        eval "tar -xf ${tar_file} -C ${d_certs_path} ./${name}.pem  && mv ${d_certs_path}${name}.pem ${d_certs_path}dashboard.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${d_certs_path} ./${name}-key.pem  && mv ${d_certs_path}${name}-key.pem ${d_certs_path}dashboard-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${d_certs_path} ./root-ca.pem ${debug}"
        eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/ ${debug}"
        eval "chmod -R 500 ${d_certs_path} ${debug}"
        eval "chmod 440 ${d_certs_path}* ${debug}"
        logger -d "Wazuh dashboard certificate setup finished."
    else
        logger -e "No certificates found. Wazuh dashboard  could not be initialized."
        exit 1
    fi

}

function dashboard_initialize() {

    logger "Starting Wazuh dashboard  (this may take a while)."
    common_getPass "admin"
    j=0

    if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
        nodes_dashboard_ip=${dashboard_node_ips[0]}
    else
        for i in "${!dashboard_node_names[@]}"; do
            if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_dashboard_ip=${dashboard_node_ips[pos]}
    fi
    until [ "$(curl -XGET https://${nodes_dashboard_ip}/status -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)" -eq "200" ] || [ "${j}" -eq "12" ]; do
        sleep 10
        j=$((j+1))
    done

    if [ "${#wazuh_servers_node_names[@]}" -eq 1 ]; then
        wazuh_api_address=${wazuh_servers_node_ips[0]}
    else
        for i in "${!wazuh_servers_node_types[@]}"; do
            if [[ "${wazuh_servers_node_types[i]}" == "master" ]]; then
                wazuh_api_address=${wazuh_servers_node_ips[i]}
            fi
        done
    fi
    eval "sed -i 's,url: https://localhost,url: https://${wazuh_api_address},g' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml ${debug}"

    if [ ${j} -eq 12 ]; then
        flag="-w"
        if [ -z "${force}" ]; then
            flag="-e"
        fi
        failed_nodes=()
        logger "${flag}" "Cannot connect to Wazuh dashboard."

        for i in "${!indexer_node_ips[@]}"; do
            curl=$(curl -XGET https://${indexer_node_ips[i]}:9700/ -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)
            exit_code=$?
            if [[ "${exit_code}" -eq "7" ]]; then
                failed_connect=1
                failed_nodes+=("${indexer_node_names[i]}")
            fi 
        done
        logger "${flag}" "Failed to connect with ${failed_nodes[*]}. Connection refused."
        if [ -z "${force}" ]; then
            logger "If want to install Wazuh dashboard without waiting for the Wazuh indexer cluster, use the -F option"
            common_rollBack
            exit 1
        else
            logger "When Wazuh dashboard is able to connect to your Elasticsearch cluster, you can access the web interface https://${nodes_dashboard_ip}. The credentials are admin:${u_pass}"
        fi
    else
        logger "You can access the web interface https://${nodes_dashboard_ip}. The credentials are admin:${u_pass}"
    fi

}

function dashboard_initializeAIO() {

    logger "Starting Wazuh dashboard (this may take a while)."
    common_getPass "admin"
    until [ "$(curl -XGET https://localhost/status -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)" -eq "200" ] || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        logger -e "Cannot connect to Wazuh dashboard."
        common_rollBack
        exit 1
    fi

    logger "Wazuh dashboard started."
    logger "You can access the web interface https://<wazuh-dashboard-host-ip>. The credentials are admin:${u_pass}"

}

function dashboard_install() {

    logger "Starting Wazuh dashboard installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-dashboard=${wazuh_version}-${wazuh_revision} ${debug}"
    elif [ "${sys_type}" == "yum" ]; then
        eval "yum install wazuh-dashboard${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "DEBIAN_FRONTEND=noninteractive apt install wazuh-dashboard${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh dashboard installation failed"
        common_rollBack
        exit 1
    else
        dashboardinstalled="1"
        logger "Wazuh dashboard installation finished."
    fi

}

