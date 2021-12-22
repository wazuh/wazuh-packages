# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

installKibana() {
    
    logger "Installing Open Distro for Kibana."
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch-kibana=${opendistro_version} ${debug}"
    else
        eval "${sys_type} install opendistroforelasticsearch-kibana${sep}${opendistro_version} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Kibana installation failed"
        rollBack
        exit 1;
    else    
        kibanainstalled="1"
        logger "Done"
    fi

}

configureKibanaAIO() {
    eval "getConfig kibana/kibana_unattended.yml /etc/kibana/kibana.yml ${debug}"
    eval "mkdir /usr/share/kibana/data ${debug}"
    eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${kibana_wazuh_module}' ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Wazuh Kibana plugin could not be installed."
        rollBack

        exit 1;
    fi     
    eval "mkdir /etc/kibana/certs ${debug}"
    copyKibanacerts
    eval "chown -R kibana:kibana /etc/kibana/ ${debug}"
    eval "chmod -R 500 /etc/kibana/certs ${debug}"
    eval "chmod 440 /etc/kibana/certs/kibana* ${debug}"
    eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"

    modifyKibanaLogin
    
    initializeKibanaAIO
}

configureKibana() {
    eval "getConfig kibana/kibana_unattended_distributed.yml /etc/kibana/kibana.yml ${debug}"
    eval "mkdir /usr/share/kibana/data ${debug}"
    eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${kibana_wazuh_module}' ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Wazuh Kibana plugin could not be installed."
        exit 1;
    fi
    eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"
    eval "mkdir /etc/kibana/certs ${debug}"

    echo 'server.host: "'${nodes_kibana_ip}'"' >> /etc/kibana/kibana.yml

    if [ ${#elasticsearch_node_names[@]} -eq 1 ]; then
        echo "elasticsearch.hosts: https://"${elasticsearch_node_ips[0]}":9200" >> /etc/kibana/kibana.yml
    else
        echo "elasticsearch.hosts:" >> /etc/kibana/kibana.yml
        for i in ${elasticsearch_node_ips[@]}; do
                echo "  - https://${i}:9200" >> /etc/kibana/kibana.yml
        done
    fi

    
    logger "Kibana installed."

    modifyKibanaLogin

    copyKibanacerts
    eval "chown -R kibana:kibana /etc/kibana/ ${debug}"
    eval "chmod -R 500 /etc/kibana/certs ${debug}"
    eval "chmod 440 /etc/kibana/certs/kibana* ${debug}"
    initializeKibana
}


copyKibanacerts() {
    if [ -d "${base_path}/certs" ]; then
        eval "cp ${base_path}/certs/kibana* /etc/kibana/certs/ ${debug}"
        eval "cp ${base_path}/certs/root-ca.pem /etc/kibana/certs/ ${debug}"
    else
        logger -e "No certificates found. Could not initialize Kibana"
        exit 1;
    fi

}

initializeKibana() {

    startService "kibana"
    logger "Initializing Kibana (this may take a while)"
    i=0
    until [[ "$(curl -XGET https://${nodes_kibana_ip}/status -I -uadmin:admin -k -s --max-time 300 | grep "200 OK")" ]] || [ ${i} -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done

    if [ ${#elasticsearch_node_names[@]} -eq 1 ]; then
        wazuh_api_address=${wazuh_servers_node_ips[0]}
    else
        for i in ${!wazuh_servers_node_types[@]}; do
            if [[ "${wazuh_servers_node_types[i]}" == "master" ]]; then
                wazuh_api_address=${wazuh_servers_node_ips[i]}
            fi
        done
    fi
    conf="$(awk '{sub("url: https://localhost", "url: https://'"${wazuh_api_address}"'")}1' /usr/share/kibana/data/wazuh/config/wazuh.yml)"
    echo "${conf}" > /usr/share/kibana/data/wazuh/config/wazuh.yml  
    logger $'\nYou can access the web interface https://'${nodes_kibana_ip}'. The credentials are admin:admin'    

}

initializeKibanaAIO() {

    startService "kibana"
    logger "Initializing Kibana (this may take a while)"
    i=0
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s --max-time 300 | grep "200 OK")" ]] || [ ${i} -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    logger $'\nYou can access the web interface https://localhost. The credentials are admin:admin'    
}

modifyKibanaLogin() {
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
