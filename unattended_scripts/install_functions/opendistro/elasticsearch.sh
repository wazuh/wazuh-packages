# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

installElasticsearch() {

    logger "Installing Open Distro for Elasticsearch..."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install opendistroforelasticsearch-${opendistro_version}-${opendistro_revision} -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch=${opendistro_version}-${opendistro_revision} ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt install elasticsearch-oss opendistroforelasticsearch -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Elasticsearch installation failed"
        rollBack
        exit 1;  
    else
        elasticsearchinstalled="1"
        logger "Done"      
    fi


}

copyCertificatesElasticsearch() {
    
    if [ ${!elasticsearch_node_names[@]} -eq 0 ]; then
        name=${elasticsearch_node_names[0]}
    else
        name=${elasticsearch_node_names[pos]}
    fi

    eval "cp ${base_path}/certs/${name}.pem /etc/elasticsearch/certs/elasticsearch.pem ${debug}"
    eval "cp ${base_path}/certs/${name}-key.pem /etc/elasticsearch/certs/elasticsearch-key.pem ${debug}"
    eval "cp ${base_path}/certs/root-ca.pem /etc/elasticsearch/certs/ ${debug}"
    eval "cp ${base_path}/certs/admin.pem /etc/elasticsearch/certs/ ${debug}"
    eval "cp ${base_path}/certs/admin-key.pem /etc/elasticsearch/certs/ ${debug}"
}

configureElasticsearchAIO() {

    logger "Configuring Elasticsearch..."

    eval "getConfig elasticsearch/elasticsearch_unattended.yml /etc/elasticsearch/elasticsearch.yml  ${debug}"
    eval "getConfig elasticsearch/roles/roles.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml  ${debug}"
    eval "getConfig elasticsearch/roles/roles_mapping.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml  ${debug}"
    eval "getConfig elasticsearch/roles/internal_users.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml  ${debug}"        
    
    eval "rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f ${debug}"

    export JAVA_HOME=/usr/share/elasticsearch/jdk/
        
    eval "mkdir /etc/elasticsearch/certs/ ${debug}"
    eval "cp ${base_path}/certs/elasticsearch* /etc/elasticsearch/certs/ ${debug}"
    eval "cp ${base_path}/certs/root-ca.pem /etc/elasticsearch/certs/ ${debug}"
    eval "cp ${base_path}/certs/admin* /etc/elasticsearch/certs/ ${debug}"
    
    # Configure JVM options for Elasticsearch
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 2 ))

    if [ ${ram} -eq "0" ]; then
        ram=1;
    fi    
    eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options ${debug}"

    eval "/usr/share/elasticsearch/bin/elasticsearch-plugin remove opendistro-performance-analyzer ${debug}"

    #Log4j remediation
    echo "-Dlog4j2.formatMsgNoLookups=true" > /etc/elasticsearch/jvm.options.d/disabledlog4j.options
    eval "chmod 2750 /etc/elasticsearch/jvm.options.d/disabledlog4j.options ${debug}"
    eval "chown root:elasticsearch /etc/elasticsearch/jvm.options.d/disabledlog4j.options ${debug}"

    startService "elasticsearch"
    logger "Initializing Elasticsearch..."
    until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
        sleep 10
    done

    eval "/usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -icl -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem ${debug}"
    logger "Done"

}

configureElasticsearch() {
    logger "Configuring Elasticsearch..."

    eval "getConfig elasticsearch/elasticsearch_unattended_distributed.yml /etc/elasticsearch/elasticsearch.yml ${debug}"
    eval "getConfig elasticsearch/roles/roles.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml ${debug}"
    eval "getConfig elasticsearch/roles/roles_mapping.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml ${debug}"
    eval "getConfig elasticsearch/roles/internal_users.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml ${debug}"
    
    if [ ${!elasticsearch_node_names[@]} -eq 0 ]; then
        pos=0
        echo "node.name: ${einame}" >> /etc/elasticsearch/elasticsearch.yml
        echo "network.host: ${elasticsearch_node_ips[0]}" >> /etc/elasticsearch/elasticsearch.yml
        echo "cluster.initial_master_nodes: ${einame}" >> /etc/elasticsearch/elasticsearch.yml

        echo "opendistro_security.nodes_dn:" >> /etc/elasticsearch/elasticsearch.yml
        echo '        - CN='${einame}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/elasticsearch/elasticsearch.yml
    else
        echo "node.name: ${einame}" >> /etc/elasticsearch/elasticsearch.yml

        echo "cluster.initial_master_nodes:" >> /etc/elasticsearch/elasticsearch.yml
        for i in ${elasticsearch_node_names[@]}; do
            echo '        - "'${$i}'"' >> /etc/elasticsearch/elasticsearch.yml
        done

        echo "discovery.seed_hosts:" >> /etc/elasticsearch/elasticsearch.yml
        for i in ${elasticsearch_node_ips[@]}; do
            echo '        - "'${i}'"' >> /etc/elasticsearch/elasticsearch.yml
        done

        for i in ${elasticsearch_node_names[@]}; do
            if [[ "${i}" == "${einame}" ]]; then
                pos="${i}";
            fi
        done

        if [[ ! "${elasticsearch_node_names[@]}" =~ "${einame}" ]]; then
            logger -e "The name given does not appear on the configuration file"
            exit 1;
        fi

        echo "network.host: ${elasticsearch_node_ips[pos]}" >> /etc/elasticsearch/elasticsearch.yml

        echo "opendistro_security.nodes_dn:" >> /etc/elasticsearch/elasticsearch.yml
        for i in "${elasticsearch_node_names[@]}"; do
                echo '        - CN='${$i}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/elasticsearch/elasticsearch.yml
        done

    fi

    eval "rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f ${debug}"
    eval "mkdir /etc/elasticsearch/certs ${debug}"

    # Configure JVM options for Elasticsearch
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 2 ))

    if [ ${ram} -eq "0" ]; then
        ram=1;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options ${debug}"

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        echo "root hard nproc 4096" >> /etc/security/limits.conf
        echo "root soft nproc 4096" >> /etc/security/limits.conf
        echo "elasticsearch hard nproc 4096" >> /etc/security/limits.conf
        echo "elasticsearch soft nproc 4096" >> /etc/security/limits.conf
        echo "bootstrap.system_call_filter: false" >> /etc/elasticsearch/elasticsearch.yml
    fi

    copyCertificatesElasticsearch

    eval "rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml -f ${debug}"
    eval "/usr/share/elasticsearch/bin/elasticsearch-plugin remove opendistro-performance-analyzer ${debug}"

    initializeElasticsearch
    logger "Done"
}

initializeElasticsearch() {

    logger "Elasticsearch installed."

    logger "Starting Elasticsearch..."
    startService "elasticsearch"
    logger "Initializing Elasticsearch..."

    until $(curl -XGET https://${elasticsearch_node_ips[pos]}:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
        sleep 10
    done

    if [ ${pos} -eq 0 ]; then
        eval "export JAVA_HOME=/usr/share/elasticsearch/jdk/"
        eval "/usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem -h ${elasticsearch_node_ips[pos]} ${debug}"
    fi

    logger "Done"
}
