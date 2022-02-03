# Wazuh installer - elasticsearch.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly e_certs_path="/etc/elasticsearch/certs/"

function applyLog4j2Mitigation() {

    eval "curl -so /tmp/apache-log4j-2.17.1-bin.tar.gz https://packages.wazuh.com/utils/log4j/apache-log4j-2.17.1-bin.tar.gz ${debug}"
    eval "tar -xf /tmp/apache-log4j-2.17.1-bin.tar.gz -C /tmp/"

    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/elasticsearch/lib/  ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/elasticsearch/lib/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-slf4j-impl-2.17.1.jar /usr/share/elasticsearch/plugins/opendistro_security/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/elasticsearch/performance-analyzer-rca/lib/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/elasticsearch/performance-analyzer-rca/lib/ ${debug}"

    eval "rm -f /usr/share/elasticsearch/lib//log4j-api-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/lib/log4j-core-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/plugins/opendistro_security/log4j-slf4j-impl-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/performance-analyzer-rca/lib/log4j-api-2.13.0.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/performance-analyzer-rca/lib/log4j-core-2.13.0.jar ${debug}"

    eval "rm -rf /tmp/apache-log4j-2.17.1-bin ${debug}"
    eval "rm -f /tmp/apache-log4j-2.17.1-bin.tar.gz ${debug}"

}

function configureElasticsearch() {

    logger -d "Configuring Elasticsearch."
    eval "export JAVA_HOME=/usr/share/elasticsearch/jdk/"
    eval "getConfig elasticsearch/roles/roles.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml ${debug}"
    eval "getConfig elasticsearch/roles/roles_mapping.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml ${debug}"
    eval "getConfig elasticsearch/roles/internal_users.yml /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml ${debug}"
    eval "rm -f /etc/elasticsearch/{esnode-key.pem,esnode.pem,kirk-key.pem,kirk.pem,root-ca.pem} ${debug}"

    copyCertificatesElasticsearch

    # Configure JVM options for Elasticsearch
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ram_gb / 2 ))

    if [ "${ram}" -eq "0" ]; then
        ram=1;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options ${debug}"

    if [ -n "${AIO}" ]; then
        eval "getConfig elasticsearch/elasticsearch_all_in_one.yml /etc/elasticsearch/elasticsearch.yml ${debug}"
    else
        eval "getConfig elasticsearch/elasticsearch_unattended_distributed.yml /etc/elasticsearch/elasticsearch.yml ${debug}"
        if [ "${#elasticsearch_node_names[@]}" -eq 1 ]; then
            pos=0
            echo "node.name: ${einame}" >> /etc/elasticsearch/elasticsearch.yml
            echo "network.host: ${elasticsearch_node_ips[0]}" >> /etc/elasticsearch/elasticsearch.yml
            echo "cluster.initial_master_nodes: ${einame}" >> /etc/elasticsearch/elasticsearch.yml

            echo "opendistro_security.nodes_dn:" >> /etc/elasticsearch/elasticsearch.yml
            echo '        - CN='${einame}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/elasticsearch/elasticsearch.yml
        else
            echo "node.name: ${einame}" >> /etc/elasticsearch/elasticsearch.yml
            echo "cluster.initial_master_nodes:" >> /etc/elasticsearch/elasticsearch.yml
            for i in "${elasticsearch_node_names[@]}"; do
                echo '        - "'${i}'"' >> /etc/elasticsearch/elasticsearch.yml
            done

            echo "discovery.seed_hosts:" >> /etc/elasticsearch/elasticsearch.yml
            for i in "${elasticsearch_node_ips[@]}"; do
                echo '        - "'${i}'"' >> /etc/elasticsearch/elasticsearch.yml
            done

            for i in "${!elasticsearch_node_names[@]}"; do
                if [[ "${elasticsearch_node_names[i]}" == "${einame}" ]]; then
                    pos="${i}";
                fi
            done

            echo "network.host: ${elasticsearch_node_ips[pos]}" >> /etc/elasticsearch/elasticsearch.yml

            echo "opendistro_security.nodes_dn:" >> /etc/elasticsearch/elasticsearch.yml
            for i in "${elasticsearch_node_names[@]}"; do
                    echo '        - CN='${i}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/elasticsearch/elasticsearch.yml
            done
        fi
    fi

    applyLog4j2Mitigation
    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        echo "root hard nproc 4096" >> /etc/security/limits.conf
        echo "root soft nproc 4096" >> /etc/security/limits.conf
        echo "elasticsearch hard nproc 4096" >> /etc/security/limits.conf
        echo "elasticsearch soft nproc 4096" >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/elasticsearch/elasticsearch.yml
    fi

    eval "/usr/share/elasticsearch/bin/elasticsearch-plugin remove opendistro-performance-analyzer ${debug}"
    eval "rm ${e_certs_path}client-certificates.readme ${e_certs_path}elasticsearch_elasticsearch_config_snippet.yml -f ${debug}"
    logger "Elasticsearch post-install configuration finished."
}

function copyCertificatesElasticsearch() {

    eval "mkdir -p ${e_certs_path} ${debug}"
    name=${elasticsearch_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${e_certs_path} ./${name}.pem  && mv ${e_certs_path}${name}.pem ${e_certs_path}elasticsearch.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${e_certs_path} ./${name}-key.pem  && mv ${e_certs_path}${name}-key.pem ${e_certs_path}elasticsearch-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${e_certs_path} ./root-ca.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${e_certs_path} ./admin.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${e_certs_path} ./admin-key.pem  ${debug}"
    else
        logger -e "No certificates found. Could not initialize Elasticsearch"
        exit 1;
    fi

}

function initializeElasticsearch() {

    logger "Starting Elasticsearch cluster."
    i=0
    until $(curl -XGET https://${elasticsearch_node_ips[pos]}:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null) || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        logger -e "Cannot start Elasticsearch cluster."
        rollBack
        exit 1
    fi
    if [ "${#elasticsearch_node_names[@]}" -eq 1 ]; then
        start_elastic_cluster=1
        startElasticsearchCluster
        changePasswords
    fi

    logger "Elasticsearch cluster started."

}

function installElasticsearch() {

    logger "Starting Open Distro for Elasticsearch installation."

    if [ "${sys_type}" == "yum" ]; then
        eval "yum install opendistroforelasticsearch-${opendistro_version}-${opendistro_revision} -y ${debug}"
    elif [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch=${opendistro_version}-${opendistro_revision} ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt install elasticsearch-oss opendistroforelasticsearch -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Elasticsearch installation failed."
        elasticsearchinstalled="elasticsearch"
        rollBack
        exit 1
    else
        elasticsearchinstalled="1"
        logger "Open Distro for Elasticsearch installation finished."
    fi

}

function uninstallelasticsearch() {
    logger "Elasticsearch will be uninstalled."

    if [[ -n "${elasticsearchinstalled}" && ( -n "${elasticsearch}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        logger -w "Removing Elasticsearch."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch -y ${debug}"
            eval "yum remove elasticsearch* -y ${debug}"
            eval "yum remove opendistro-* -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-* ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge ^elasticsearch* ^opendistro-* ^opendistroforelasticsearch -y ${debug}"
        fi
    fi

    if [[ ( -n "${elastic_remaining_files}" || -n "${elasticsearchinstalled}" ) && ( -n "${elasticsearch}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/elasticsearch/ ${debug}"
        eval "rm -rf /usr/share/elasticsearch/ ${debug}"
        eval "rm -rf /etc/elasticsearch/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/elasticsearch/"
                            "/etc/systemd/system/elasticsearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/elasticsearch.service"
                            "/etc/systemd/system/multi-user.target.wants/kibana.service"
                            "/etc/systemd/system/kibana.service"
                            "/lib/firewalld/services/kibana.xml"
                            "/lib/firewalld/services/elasticsearch.xml" )

    eval "rm -rf ${elements_to_remove[*]}"
}


function startElasticsearchCluster() {

    eval "elasticsearch_cluster_ip=( $(cat /etc/elasticsearch/elasticsearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "export JAVA_HOME=/usr/share/elasticsearch/jdk/"
    eval "/usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -icl -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem -h ${elasticsearch_cluster_ip} > /dev/null ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The Elasticsearch cluster security configuration could not be initialized."
        rollBack
        exit 1
    else
        logger "Elasticsearch cluster security configuration initialized."
    fi
    eval "curl --silent ${filebeat_wazuh_template} | curl -X PUT 'https://${elasticsearch_node_ips[pos]}:9200/_template/wazuh' -H 'Content-Type: application/json' -d @- -uadmin:admin -k --silent ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The wazuh-alerts template could not be inserted into the Elasticsearch cluster."
        rollBack
        exit 1
    else
        logger -d "wazuh-alerts template inserted into the Elasticsearch cluster."
    fi

}