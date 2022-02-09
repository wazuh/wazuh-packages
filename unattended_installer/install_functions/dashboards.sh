# Wazuh installer - dashboards.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly d_certs_path="/etc/wazuh-dashboards/certs/"

function dashboards_configure() {

    dashboards_copyCertificates

    if [ -n "${AIO}" ]; then
        eval "common_getConfig dashboards/dashboards_unattended.yml /etc/wazuh-dashboards/dashboards.yml ${debug}"
    else
        eval "common_getConfig dashboards/dashboards_unattended_distributed.yml /etc/wazuh-dashboards/dashboards.yml ${debug}"
        if [ "${#dashboards_node_names[@]}" -eq 1 ]; then
            pos=0
            ip=${dashboards_node_ips[0]}
        else
            for i in "${!dashboards_node_names[@]}"; do
                if [[ "${dashboards_node_names[i]}" == "${dashname}" ]]; then
                    pos="${i}";
                fi
            done
            ip=${dashboards_node_ips[pos]}
        fi

        echo 'server.host: "'${ip}'"' >> /etc/wazuh-dashboards/dashboards.yml

        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            echo "opensearch.hosts: https://"${indexer_node_ips[0]}":9700" >> /etc/wazuh-dashboards/dashboards.yml
        else
            echo "opensearch.hosts:" >> /etc/wazuh-dashboards/dashboards.yml
            for i in "${indexer_node_ips[@]}"; do
                    echo "  - https://${i}:9700" >> /etc/wazuh-dashboards/dashboards.yml
            done
        fi
    fi

    logger "Wazuh dashboards post-install configuration finished."

}

function dashboards_copyCertificates() {

    eval "rm -f ${d_certs_path}/* ${debug}"
    if [ -f "${tar_file}" ]; then

        name=${dashboards_node_names[pos]}

        eval "tar -xf ${tar_file} -C ${d_certs_path} ./${name}.pem  && mv ${d_certs_path}${name}.pem ${d_certs_path}dashboards.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${d_certs_path} ./${name}-key.pem  && mv ${d_certs_path}${name}-key.pem ${d_certs_path}dashboards-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${d_certs_path} ./root-ca.pem ${debug}"
        eval "chown -R wazuh-dashboards:wazuh-dashboards /etc/wazuh-dashboards/ ${debug}"
        eval "chmod -R 500 ${d_certs_path} ${debug}"
        eval "chmod 440 ${d_certs_path}* ${debug}"
        logger -d "Wazuh dashboards certificate setup finished."
    else
        logger -e "No certificates found. Wazuh dashboards  could not be initialized."
        exit 1
    fi

}

function dashboards_initialize() {

    logger "Starting Wazuh dashboards  (this may take a while)."
    common_getPass "admin"
    j=0

    if [ "${#dashboards_node_names[@]}" -eq 1 ]; then
        nodes_dashboards_ip=${dashboards_node_ips[0]}
    else
        for i in "${!dashboards_node_names[@]}"; do
            if [[ "${dashboards_node_names[i]}" == "${dashname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_dashboards_ip=${dashboards_node_ips[pos]}
    fi
    until [ "$(curl -XGET https://${nodes_dashboards_ip}/status -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)" -eq "200" ] || [ "${j}" -eq "12" ]; do
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
    eval "sed -i 's,url: https://localhost,url: https://${wazuh_api_address},g' /usr/share/wazuh-dashboards/data/wazuh/config/wazuh.yml ${debug}"

    if [ ${j} -eq 12 ]; then
        flag="-w"
        if [ -z "${force}" ]; then
            flag="-e"
        fi
        failed_nodes=()
        logger "${flag}" "Cannot connect to Wazuh dashboards."

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
            logger "If want to install Wazuh dashboards without waiting for the Wazuh indexer cluster, use the -F option"
            common_rollBack
            exit 1
        else
            logger "When Wazuh dashboards is able to connect to your Elasticsearch cluster, you can access the web interface https://${nodes_dashboards_ip}. The credentials are admin:${u_pass}"
        fi
    else
        logger "You can access the web interface https://${nodes_dashboards_ip}. The credentials are admin:${u_pass}"
    fi

}

function dashboards_initializeAIO() {

    logger "Starting Wazuh dashboards (this may take a while)."
    common_getPass "admin"
    until [ "$(curl -XGET https://localhost/status -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)" -eq "200" ] || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        logger -e "Cannot connect to Wazuh dashboards."
        common_rollBack
        exit 1
    fi
    logger "Wazuh dashboards started."
    logger "You can access the web interface https://<wazuh-dashboards-host-ip>. The credentials are admin:${u_pass}"

}

function dashboards_install() {

    logger "Starting Wazuh dashboards installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-dashboards=${wazuh_version}-${wazuh_revision} ${debug}"
    else
        eval "${sys_type} install wazuh-dashboards${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh dashboards installation failed"
        common_rollBack
        exit 1
    else
        dashboardsinstalled="1"
        logger "Wazuh dashboards installation finished."
    fi

}

function dashboards_uninstall() {

    logger "Starting Wazuh dashboards uninstall."

    if [[ -n "${dashboardsinstalled}" ]]; then
        logger -w "Removing Wazuh dashboards packages."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-dashboards -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-dashboards ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-dashboards -y ${debug}"
        fi
    fi

    if [[ -n "${dashboards_remaining_files}" ]]; then
        logger -w "Removing Wazuh dashboards files."

        elements_to_remove=(    "/etc/systemd/system/multi-user.target.wants/wazuh-dashboards.service"
                                "/etc/systemd/system/wazuh-dashboards.service"
                                "/lib/firewalld/services/dashboards.xml"
                                "/usr/share/wazuh-dashboards"
                                "/run/wazuh-dashboards/"
                                "/etc/wazuh-dashboards/"
                                "/var/lib/wazuh-dashboards/" )

        eval "rm -rf ${elements_to_remove[*]} ${debug}"
    fi

}