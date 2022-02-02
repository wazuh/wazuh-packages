# Wazuh installer - indexer.sh functions. 
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly i_certs_path="/etc/wazuh-indexer/certs/"

function indexer_configure() {

    logger -d "Configuring Wazuh indexer."
    eval "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/"
    # eval "getConfig indexer/roles/roles.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles.yml ${debug}"
    # eval "getConfig indexer/roles/roles_mapping.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/roles_mapping.yml ${debug}"
    # eval "getConfig indexer/roles/internal_users.yml /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/internal_users.yml ${debug}"
    # eval "rm -f /etc/wazuh-indexer/{esnode-key.pem,esnode.pem,kirk-key.pem,kirk.pem,root-ca.pem} ${debug}"
    
    indexer_copyCertificates

    # Configure JVM options for Wazuh indexer
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ram_gb / 2 ))

    if [ "${ram}" -eq "0" ]; then
        ram=1;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/wazuh-indexer/jvm.options ${debug}"

    if [ -n "${AIO}" ]; then
        eval "getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    else
        eval "getConfig indexer/indexer_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            pos=0
            echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
            echo "network.host: ${indexer_node_ips[0]}" >> /etc/wazuh-indexer/opensearch.yml
            echo "cluster.initial_master_nodes: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
            echo '        - CN='${indxname}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/wazuh-indexer/opensearch.yml
        else
            eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
            echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
            echo "cluster.initial_master_nodes:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                echo '        - "'${i}'"' >> /etc/wazuh-indexer/opensearch.yml
            done

            echo "discovery.seed_hosts:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_ips[@]}"; do
                echo '        - "'${i}'"' >> /etc/wazuh-indexer/opensearch.yml
            done

            for i in "${!indexer_node_names[@]}"; do
                if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
                    pos="${i}";
                fi
            done

            echo "network.host: ${indexer_node_ips[pos]}" >> /etc/wazuh-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                    echo '        - CN='${i}',OU=Docu,O=Wazuh,L=California,C=US' >> /etc/wazuh-indexer/opensearch.yml
            done
        fi
    fi

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/wazuh-indexer/opensearch.yml
    fi
    ## preguntar si aun hace falta quitarlo
    # eval "/usr/share/wazuh-indexer/bin/opensearch-plugin remove opendistro-performance-analyzer ${debug}"
    logger "Wazuh indexer post-install configuration finished."
}

function indexer_copyCertificates() {
    
    eval "rm -f ${i_certs_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./${name}.pem  && mv ${i_certs_path}${name}.pem ${i_certs_path}indexer.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./${name}-key.pem  && mv ${i_certs_path}${name}-key.pem ${i_certs_path}indexer-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./root-ca.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./admin.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./admin-key.pem  ${debug}"
    else
        logger -e "No certificates found. Could not initialize Wazuh indexer"
        exit 1;
    fi

}

function indexer_initialize() {

    logger "Starting Wazuh indexer cluster."
    i=0
    until $(curl -XGET https://${indexer_node_ips[pos]}:9700/ -uadmin:admin -k --max-time 120 --silent --output /dev/null) || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        logger -e "Cannot start Wazuh indexer cluster."
        rollBack
        exit 1
    fi
    if [ "${#indexer_node_names[@]}" -eq 1 ] && [ -z "${AIO}" ]; then
        changePasswords
    fi

    logger "Wazuh indexer cluster started."

}

function indexer_install() {

    logger "Starting Wazuh indexer installation."

    if [ "${sys_type}" == "yum" ]; then
        eval "yum install wazuh-indexer-${wazuh_version}-${wazuh_revision} -y ${debug}"
    elif [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-indexer=${wazuh_version}-${wazuh_revision} ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt install wazuh-indexer=${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Wazuh indexer installation failed."
        rollBack
        exit 1
    else
        indexerchinstalled="1"
        logger "Wazuh indexer installation finished."
    fi

}

function indexer_startCluster() {

    eval "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/"
    eval "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -p 9800 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ -icl -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem -cert /etc/wazuh-indexer/certs/admin.pem -key /etc/wazuh-indexer/certs/admin-key.pem -h ${indexer_node_ips[pos]} > /dev/null ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        rollBack
        exit 1
    else
        logger "Wazuh indexer cluster security configuration initialized."
    fi
    eval "curl --silent ${filebeat_wazuh_template} | curl -X PUT 'https://${indexer_node_ips[pos]}:9700/_template/wazuh' -H 'Content-Type: application/json' -d @- -uadmin:admin -k --silent ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The wazuh-alerts template could not be inserted into the Wazuh indexer cluster."
        rollBack
        exit 1
    else
        logger -d "The wazuh-alerts template inserted into the Wazuh indexer cluster."
    fi

}