# Wazuh installer - dashboard.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function dashboard_configure() {

    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig dashboard/dashboard_unattended.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates
    else
        eval "installCommon_getConfig dashboard/dashboard_unattended_distributed.yml /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates
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

        echo 'server.host: "'${ip}'"' >> /etc/wazuh-dashboard/opensearch_dashboards.yml

        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            echo "opensearch.hosts: https://"${indexer_node_ips[0]}":9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
        else
            echo "opensearch.hosts:" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
            for i in "${indexer_node_ips[@]}"; do
                    echo "  - https://${i}:9200" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
            done
        fi
    fi

    common_logger "Wazuh dashboard post-install configuration finished."

}

function dashboard_copyCertificates() {

    eval "rm -f ${dashboard_cert_path}/* ${debug}"
    name=${dashboard_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        eval "mkdir ${dashboard_cert_path} ${debug}"
        eval "sed -i s/dashboard.pem/${name}.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "sed -i s/dashboard-key.pem/${name}-key.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/ ${debug}"
        eval "chmod 500 ${dashboard_cert_path} ${debug}"
        eval "chmod 400 ${dashboard_cert_path}/* ${debug}"
        eval "chown wazuh-dashboard:wazuh-dashboard ${dashboard_cert_path}/* ${debug}"
        common_logger -d "Wazuh dashboard certificate setup finished."
    else
        common_logger -e "No certificates found. Wazuh dashboard  could not be initialized."
        exit 1
    fi

}

function dashboard_initialize() {

    common_logger "Initializing Wazuh dashboard web application."
    installCommon_getPass "admin"
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

    if [ "${#server_node_names[@]}" -eq 1 ]; then
        wazuh_api_address=${server_node_ips[0]}
    else
        for i in "${!server_node_types[@]}"; do
            if [[ "${server_node_types[i]}" == "master" ]]; then
                wazuh_api_address=${server_node_ips[i]}
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
        common_logger "${flag}" "Cannot connect to Wazuh dashboard."

        for i in "${!indexer_node_ips[@]}"; do
            curl=$(curl -XGET https://${indexer_node_ips[i]}:9200/ -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)
            exit_code=$?
            if [[ "${exit_code}" -eq "7" ]]; then
                failed_connect=1
                failed_nodes+=("${indexer_node_names[i]}")
            fi
        done
        common_logger "${flag}" "Failed to connect with ${failed_nodes[*]}. Connection refused."
        if [ -z "${force}" ]; then
            common_logger "If want to install Wazuh dashboard without waiting for the Wazuh indexer cluster, use the -F option"
            installCommon_rollBack
            exit 1
        else
            common_logger "--- Summary ---"
            common_logger "When Wazuh dashboard is able to connect to your Elasticsearch cluster, you can access the web interface https://${nodes_dashboard_ip}.\n    User: admin\n    Password: ${u_pass}"
            common_logger "The password can be seen in the file ${logfile}"
        fi
    else
        common_logger "Wazuh dashboard web application initialized."
        common_logger "--- Summary ---"
        common_logger "You can access the web interface https://${nodes_dashboard_ip}.\n    User: admin\n    Password: ${u_pass}"
        common_logger "Remember that the password can be seen in the file ${logfile}"
    fi

}

function dashboard_initializeAIO() {

    common_logger "Initializing Wazuh dashboard web application."
    installCommon_getPass "admin"
    until [ "$(curl -XGET https://localhost/status -uadmin:${u_pass} -k -w %{http_code} -s -o /dev/null)" -eq "200" ] || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        common_logger -e "Cannot connect to Wazuh dashboard."
        installCommon_rollBack
        exit 1
    fi

    common_logger "Wazuh dashboard web application initialized."
    common_logger "--- Summary ---"
    common_logger "You can access the web interface https://<wazuh-dashboard-ip>.\n    User: admin\n    Password: ${u_pass}"
    common_logger "Remember that the password can be seen in the file ${logfile}"

}

function dashboard_install() {

    common_logger "Starting Wazuh dashboard installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-dashboard=${wazuh_version}-${wazuh_revision} ${debug}"
        install_result="$?"
    elif [ "${sys_type}" == "yum" ]; then
        eval "yum install wazuh-dashboard${sep}${wazuh_version}-${wazuh_revision} -y ${debug}"
        install_result="$?"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "wazuh-dashboard" "${wazuh_version}-${wazuh_revision}"
    fi
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh dashboard installation finished."
    fi

}
