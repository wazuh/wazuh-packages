# Wazuh installer - kibana.sh library. 
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

k_certs_path="/etc/kibana/certs/"

function configureKibana() {

    eval "getConfig kibana/kibana_unattended_distributed.yml /etc/kibana/kibana.yml ${debug}"
    eval "mkdir /usr/share/kibana/data ${debug}"
    eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install ${kibana_wazuh_plugin} ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Wazuh Kibana plugin could not be installed."
        exit 1
    fi
    logger "Wazuh Kibana plugin installed."
    eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"

    if [ "${#kibana_node_names[@]}" -eq 1 ]; then
        ip=${kibana_node_ips[0]}
    else
        for i in ${!kibana_node_names[@]}; do
            if [[ "${kibana_node_names[i]}" == "${kiname}" ]]; then
                pos="${i}";
            fi
        done
        ip=${kibana_node_ips[pos]}
    fi

    echo 'server.host: "'${ip}'"' >> /etc/kibana/kibana.yml

    if [ "${#elasticsearch_node_names[@]}" -eq 1 ]; then
        echo "elasticsearch.hosts: https://"${elasticsearch_node_ips[0]}":9200" >> /etc/kibana/kibana.yml
    else
        echo "elasticsearch.hosts:" >> /etc/kibana/kibana.yml
        for i in ${elasticsearch_node_ips[@]}; do
                echo "  - https://${i}:9200" >> /etc/kibana/kibana.yml
        done
    fi

    modifyKibanaLogin
    copyKibanacerts

}

function configureKibanaAIO() {

    logger "Starting Wazuh Kibana plugin installation."
    
    eval "getConfig kibana/kibana_unattended.yml /etc/kibana/kibana.yml ${debug}"
    eval "mkdir /usr/share/kibana/data ${debug}"
    eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${kibana_wazuh_plugin}' ${debug}"
    if [ "$?" != 0  ]; then
        logger -e "Wazuh Kibana plugin could not be installed."
        rollBack
        exit 1
    fi
    logger "Wazuh Kibana plugin installation finished."
    copyKibanacerts
    eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"
    modifyKibanaLogin
    logger "Kibana post-install configuration finished."

}

function copyKibanacerts() {

    eval "mkdir /etc/kibana/certs ${debug}"
    if [ -f "${tar_file}" ]; then
        if [ "${#kibana_node_names[@]}" -eq 1 ]; then
            name=${kiname}
        else
            name=${kibana_node_names[pos]}
        fi

        eval "tar -xf ${tar_file} -C ${k_certs_path} ./${name}.pem  && mv ${k_certs_path}${name}.pem ${k_certs_path}kibana.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${k_certs_path} ./${name}-key.pem  && mv ${k_certs_path}${name}-key.pem ${k_certs_path}kibana-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${k_certs_path} ./root-ca.pem ${debug}"
        eval "chown -R kibana:kibana /etc/kibana/ ${debug}"
        eval "chmod -R 500 /etc/kibana/certs ${debug}"
        eval "chmod 440 /etc/kibana/certs/* ${debug}"
        logger "Kibana certificate setup finished."
    else
        logger -e "No certificates found. Kibana could not be initialized."
        exit 1
    fi

}

function initializeKibana() {

    logger "Starting Kibana (this may take a while)."
    getPass "admin"
    i=0
    if [ "${#kibana_node_names[@]}" -eq 1 ]; then
        nodes_kibana_ip=${kibana_node_ips[0]}
    else
        for i in ${!kibana_node_names[@]}; do
            if [[ "${kibana_node_names[i]}" == "${kiname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_kibana_ip=${kibana_node_ips[pos]}
    fi
    until [[ "$(curl -XGET https://${nodes_kibana_ip}/status -I -uadmin:${u_pass} -k -s --max-time 300 | grep "200 OK")" ]] || [ ${i} -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ $i -eq 12 ]; then
        logger -e "Cannot connect to Kibana."
        rollBack
        exit 1
    fi
    if [ "${#wazuh_servers_node_names[@]}" -eq 1 ]; then
        wazuh_api_address=${wazuh_servers_node_ips[0]}
    else
        for i in ${!wazuh_servers_node_types[@]}; do
            if [[ "${wazuh_servers_node_types[i]}" == "master" ]]; then
                wazuh_api_address=${wazuh_servers_node_ips[i]}
            fi
        done
    fi
    eval "sed -i 's,url: https://localhost,url: https://${wazuh_api_address},g' /usr/share/kibana/data/wazuh/config/wazuh.yml ${debug}"
    logger "Kibana started."
    logger "You can access the web interface https://${nodes_kibana_ip}. The credentials are admin:${u_pass}"

}

function initializeKibanaAIO() {

    logger "Starting Kibana (this may take a while)."
    getPass "admin"
    i=0
    if [ "${#kibana_node_names[@]}" -eq 1 ]; then
        nodes_kibana_ip=${kibana_node_ips[0]}
    else
        for i in ${!kibana_node_names[@]}; do
            if [[ "${kibana_node_names[i]}" == "${kiname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_kibana_ip=${kibana_node_ips[pos]}
    fi
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:${u_pass} -k -s --max-time 300 | grep "200 OK")" ]] || [ ${i} -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    logger "Kibana started."
    logger "You can access the web interface https://<kibana-host-ip>. The credentials are admin:${u_pass}"

}

function installKibana() {
    
    logger "Starting Kibana installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch-kibana=${opendistro_version} ${debug}"
    else
        eval "${sys_type} install opendistroforelasticsearch-kibana${sep}${opendistro_version} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Kibana installation failed"
        rollBack
        exit 1
    else    
        kibanainstalled="1"
        logger "Kibana installation finished."
    fi

}

function modifyKibanaLogin() {

    # Edit window title
    eval "sed -i 's/null, \"Elastic\"/null, \"Wazuh\"/g' /usr/share/kibana/src/core/server/rendering/views/template.js ${debug}"

    # Edit background and logos
    eval "curl -so /tmp/custom_welcome.tar.gz https://wazuh-demo.s3-us-west-1.amazonaws.com/custom_welcome_opendistro_docker.tar.gz ${debug}"
    eval "tar -xf /tmp/custom_welcome.tar.gz -C /tmp ${debug}"
    eval "rm -f /tmp/custom_welcome.tar.gz ${debug}"
    eval "cp /tmp/custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/src/core/server/core_app/assets/ ${debug}"
    eval "cp /tmp/custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/src/core/server/core_app/assets/ ${debug}"
    eval "cp -f /tmp/custom_welcome/template.js.hbs /usr/share/kibana/src/legacy/ui/ui_render/bootstrap/template.js.hbs ${debug}"
    eval "rm -f /tmp/custom_welcome/* ${debug}"
    eval "rmdir /tmp/custom_welcome ${debug}"

    # Edit CSS theme
    eval "getConfig kibana/customWelcomeKibana.css /tmp/ ${debug}"
    eval "cat /tmp//customWelcomeKibana.css | tee -a /usr/share/kibana/src/core/server/core_app/assets/legacy_light_theme.css ${debug}"
    eval "rm -f /tmp/customWelcomeKibana.css"

}
