# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

installKibana() {
    
    logger "Installing Open Distro for Kibana..."
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
    eval "cd /usr/share/kibana ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${repobaseurl}'/ui/kibana/wazuh_kibana-${wazuh_version}_${elastic_oss_version}-${wazuh_kibana_plugin_revision}.zip ${debug}"
    eval "cd ${base_path} ${debug}"
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

    # Start Kibana
    startService "kibana"
}

configureKibana() {
    eval "getConfig kibana/kibana_unattended_distributed.yml /etc/kibana/kibana.yml ${debug}"
    eval "mkdir /usr/share/kibana/data ${debug}"
    eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
    eval "cd /usr/share/kibana ${debug}"
    eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${repobaseurl}'/ui/kibana/wazuh_kibana-${wazuh_version}_${elastic_oss_version}-${wazuh_kibana_plugin_revision}.zip ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Wazuh Kibana plugin could not be installed."
        exit 1;
    fi
    eval "cd ${base_path} ${debug}"
    eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"
    eval "mkdir /etc/kibana/certs ${debug}"

    kip=$(grep -A 1 "Kibana-instance" ./config.yml | tail -1)
    rm="- "
    kip="${kip//$rm}"
    echo 'server.host: "'${kip}'"' >> /etc/kibana/kibana.yml
    nh=$(awk -v RS='' '/network.host:/' ./config.yml)

    if [ -n "${nh}" ]; then
        nhr="network.host: "
        eip="${nh//$nhr}"
        echo "elasticsearch.hosts: https://"${eip}":9200" >> /etc/kibana/kibana.yml
    else
        echo "elasticsearch.hosts:" >> /etc/kibana/kibana.yml
        sh=$(awk -v RS='' '/discovery.seed_hosts:/' ./config.yml)
        shr="discovery.seed_hosts:"
        rm="- "
        sh="${sh//$shr}"
        sh="${sh//$rm}"
        for line in $sh; do
                echo "  - https://${line}:9200" >> /etc/kibana/kibana.yml
        done
    fi

    
    logger "Kibana installed."

    copyKibanacerts
    initializeKibana kip
}


copyKibanacerts() {
    if [ -d "${base_path}/certs" ]; then
        eval "cp ${base_path}/certs/kibana* /etc/kibana/certs/ ${debug}"
        eval "cp ${base_path}/certs/root-ca.pem /etc/kibana/certs/ ${debug}"
    else
        logger "No certificates found. Could not initialize Kibana"
        exit 1;
    fi

}

initializeKibana() {

    # Start Kibana
    startService "kibana"
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://${kip}/status -I -uadmin:admin -k -s --max-time 300 | grep "200 OK")" ]]; do
        echo -ne ${char}
        sleep 10
    done
    echo ""
    wip=$(grep -A 1 "Wazuh-master-configuration" ./config.yml | tail -1)
    rm="- "
    wip="${wip//$rm}"
    conf="$(awk '{sub("url: https://localhost", "url: https://'"${wip}"'")}1' /usr/share/kibana/data/wazuh/config/wazuh.yml)"
    echo "${conf}" > /usr/share/kibana/data/wazuh/config/wazuh.yml  
    logger $'\nYou can access the web interface https://'${kip}'. The credentials are admin:admin'    

}
